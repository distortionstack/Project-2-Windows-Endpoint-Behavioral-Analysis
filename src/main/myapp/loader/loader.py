"""loader.py — Load raw Windows event data from local files, URLs, and archives.

OOM-safe: uses Polars Lazy API (scan_ndjson + streaming) for large NDJSON/JSONL datasets.
"""

from __future__ import annotations

import io
import json as _json
import logging
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse
from zipfile import ZipFile

import numpy as np
import pandas as pd
import polars as pl
import requests

from src.main.myapp.config.constants import ARCHIVE_SUFFIXES, DATA_SUFFIXES, CACHE_DIR

logger = logging.getLogger(__name__)


def safe_col(df, *names, default=np.nan, as_str=False):
    for name in names:
        if name in df.columns:
            res = df[name]
            return res.astype(str) if as_str else res
    series = pd.Series(default, index=df.index)
    return series.astype(str) if as_str else series


def _source_key(sources):
    return "\n".join(map(str, sources))


def _as_sources(sources):
    if isinstance(sources, (str, Path)):
        return [str(sources)]
    return [str(s) for s in sources]


def _is_url(source: str) -> bool:
    return urlparse(str(source)).scheme in {"http", "https"}


def _local_path(source: str) -> Path:
    parsed = urlparse(str(source))
    if parsed.scheme == "file":
        return Path(unquote(parsed.path)).expanduser()
    return Path(str(source)).expanduser()


def _extension(name: str) -> str:
    lower = str(name).lower()
    for suffix in ARCHIVE_SUFFIXES + DATA_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return Path(lower).suffix


def _flatten_structs(df: pl.DataFrame) -> pl.DataFrame:
    changed = True
    while changed:
        changed = False
        new_cols: list[pl.Expr] = []
        drop_cols: list[str] = []
        for col_name, dtype in zip(df.columns, df.dtypes):
            if isinstance(dtype, pl.Struct):
                for field in dtype.fields:
                    flat_name = f"{col_name}.{field.name}"
                    new_cols.append(
                        pl.col(col_name).struct.field(field.name).alias(flat_name)
                    )
                drop_cols.append(col_name)
                changed = True
        if changed:
            df = df.with_columns(new_cols).drop(drop_cols)
    return df


def _scan_ndjson_file(path: Path) -> pd.DataFrame:
    lf = pl.scan_ndjson(str(path))
    df_pl = lf.collect()
    df_pl = _flatten_structs(df_pl)
    return df_pl.to_pandas()


def _scan_json_array_file(path: Path) -> pd.DataFrame:
    df_pl = pl.read_json(str(path))
    df_pl = _flatten_structs(df_pl)
    return df_pl.to_pandas()


def _read_json_bytes(data: bytes, label: str) -> pd.DataFrame:
    text = data.decode("utf-8-sig")
    first_char = text.lstrip()[:1]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ndjson", delete=False, encoding="utf-8",
    ) as tmp:
        tmp_path = Path(tmp.name)

        if first_char == "[":
            try:
                rows = _json.loads(text)
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    tmp.write(_json.dumps(row) + "\n")
            except _json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {label}: {exc}") from exc
        else:
            tmp.write(text)

    try:
        return _scan_ndjson_file(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _read_csv_bytes(data: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(data))


def _read_xml_bytes(data: bytes, label: str) -> pd.DataFrame:
    try:
        return pd.read_xml(io.StringIO(data.decode("utf-8-sig")))
    except Exception as exc:
        raise ValueError(f"Failed to parse XML in {label}: {exc}") from exc


def _read_non_archive(data: bytes, label: str) -> pd.DataFrame:
    ext = _extension(label)
    if ext == ".csv":
        return _read_csv_bytes(data)
    if ext in {".json", ".jsonl", ".ndjson"}:
        return _read_json_bytes(data, label)
    if ext == ".xml":
        return _read_xml_bytes(data, label)
    raise ValueError(f"Unsupported data file type: {label}")


def _read_zip(data: bytes, label: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    with ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if _extension(name) in DATA_SUFFIXES:
                frames.append(_read_non_archive(archive.read(name), name))
    if not frames:
        raise ValueError(f"No JSON/CSV files found inside archive: {label}")
    return pd.concat(frames, ignore_index=True)


def _read_tar(data: bytes, label: str) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            if member.isfile() and _extension(member.name) in DATA_SUFFIXES:
                extracted = archive.extractfile(member)
                if extracted is not None:
                    frames.append(_read_non_archive(extracted.read(), member.name))
    if not frames:
        raise ValueError(f"No JSON/CSV files found inside archive: {label}")
    return pd.concat(frames, ignore_index=True)


def _read_bytes(data: bytes, label: str) -> pd.DataFrame:
    ext = _extension(label)
    if ext == ".zip":
        return _read_zip(data, label)
    if ext in {".tar", ".tar.gz", ".tgz"}:
        return _read_tar(data, label)
    return _read_non_archive(data, label)


def _load_url(source: str) -> pd.DataFrame:
    response = requests.get(source, timeout=60)
    response.raise_for_status()
    return _read_bytes(response.content, urlparse(source).path or source)


def _load_local_file(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Local file not found: {path}")
    ext = _extension(path.name)
    if ext in {".jsonl", ".ndjson"}:
        return _scan_ndjson_file(path)
    return _read_bytes(path.read_bytes(), path.name)


def _load_local_dir(path: Path) -> pd.DataFrame:
    files = [
        fp for fp in path.rglob("*")
        if fp.is_file() and _extension(fp.name) in DATA_SUFFIXES + ARCHIVE_SUFFIXES
    ]
    if not files:
        raise ValueError(f"No supported files found in directory: {path}")
    return pd.concat(
        [_load_local_file(fp) for fp in sorted(files)], ignore_index=True
    )


def load_source(source: str) -> pd.DataFrame:
    if _is_url(source):
        print(f"[*] Downloading: {source}")
        return _load_url(source)
    path = _local_path(source)
    print(f"[*] Loading local: {path}")
    return _load_local_dir(path) if path.is_dir() else _load_local_file(path)
