"""loader.py — Load & normalize raw Sysmon/Mordor logs into a standard DataFrame"""

from io import BytesIO
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile
import numpy as np
import pandas as pd
import requests
import os

def safe_col(df, *names, default=np.nan):
    for n in names:
        if n in df.columns:
            return df[n]
    return pd.Series(default, index=df.index)


def load_dataset(source):
    """Load from URL(s) (zip), or local .json / .jsonl / .xml / .csv"""
    Path("uploads").mkdir(exist_ok=True)
    out_file = Path("uploads/uploads.json")
    
    if isinstance(source, list):
        frames = []
        for url in source:
            if str(url).startswith("http"):
                print(f"Downloading {url} ...")
                zf = ZipFile(BytesIO(requests.get(url).content))
                extracted_file = zf.extract(zf.namelist()[0])
                df = pd.read_json(extracted_file, lines=True)
                frames.append(df)
                os.remove(extracted_file)
            else:
                p = Path(url)
                if p.suffix in (".json", ".jsonl"):
                    frames.append(pd.read_json(p, lines=True))
        
        combined = pd.concat(frames, ignore_index=True)
        # Overwrite to uploads.json
        combined.to_json(out_file, orient="records", lines=True)
        return combined

    if str(source).startswith("http"):
        zf = ZipFile(BytesIO(requests.get(source).content))
        extracted = zf.extract(zf.namelist()[0])
        df = pd.read_json(extracted, lines=True)
        # Overwrite to uploads.json
        df.to_json(out_file, orient="records", lines=True)
        os.remove(extracted)
        return df

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
