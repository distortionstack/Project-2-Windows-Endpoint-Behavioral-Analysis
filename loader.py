"""loader.py — Load & normalize raw Sysmon/Mordor logs into a standard DataFrame"""

from io import BytesIO
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile
import numpy as np
import pandas as pd
import requests


def safe_col(df, *names, default=np.nan):
    for n in names:
        if n in df.columns:
            return df[n]
    return pd.Series(default, index=df.index)


def load_dataset(source):
    """Load from URL (zip), or local .json / .jsonl / .xml / .csv"""
    if str(source).startswith("http"):
        zf = ZipFile(BytesIO(requests.get(source).content))
        source = zf.extract(zf.namelist()[0])
    p = Path(source)
    if p.suffix in (".json", ".jsonl"):
        return pd.read_json(p, lines=True)
    elif p.suffix == ".xml":
        tree = ET.parse(p)
        rows = [{c.tag: c.text for c in event} for event in tree.getroot()]
        return pd.DataFrame(rows)
    else:
        return pd.read_csv(p, low_memory=False)


def normalize(df):
    """Normalize Sysmon/Security log column names into generic _process, _parent etc."""
    df["@timestamp"]       = pd.to_datetime(df.get("@timestamp"), utc=True, errors="coerce")
    df                     = df.dropna(subset=["@timestamp"]).copy()
    df["_process"]         = safe_col(df, "Image", "NewProcessName").astype(str)
    df["_parent"]          = safe_col(df, "ParentImage", "ParentProcessName").astype(str)
    df["_cmd"]             = safe_col(df, "CommandLine").astype(str)
    df["_host"]            = safe_col(df, "Hostname", "Computer").fillna("UNKNOWN").astype(str)
    df["_user"]            = safe_col(df, "User").fillna("UNKNOWN").astype(str)
    df["_image_loaded"]    = safe_col(df, "ImageLoaded").astype(str)
    df["_target_image"]    = safe_col(df, "TargetImage").astype(str)
    df["_target_filename"] = safe_col(df, "TargetFilename").astype(str)
    return df
