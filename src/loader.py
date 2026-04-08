"""
loader.py — Load & normalize raw Sysmon/Mordor logs into a standard DataFrame
Task 1: Smart Data Loader with State Tracking
"""

import os
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import numpy as np
import pandas as pd
import requests

def safe_col(df, *names, default=np.nan):
    """
    Safely get the first matching column in names.
    Preserved for compatibility with detection.py
    """
    for n in names:
        if n in df.columns:
            return df[n]
    return pd.Series(default, index=df.index)

def get_smart_data(urls, force_update=False):
    """
    ตรวจสอบ URL กับไฟล์ tracker ถ้าซ้ำให้โหลดจาก cache (current_dataset.json)
    ถ้าไม่ซ้ำ ให้โหลดใหม่ แปลงเป็น JSON และเขียนทับของเดิมทันที
    """
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    state_file = raw_dir / "source_url.txt"
    data_file = raw_dir / "current_dataset.json"
    
    # แปลง List ของ URLs เป็น String เพื่อใช้เปรียบเทียบ
    urls_key = ",".join(urls) if isinstance(urls, list) else urls
    
    # 1. อ่าน URL เก่าจากไฟล์ source_url.txt
    current_stored_url = None
    if state_file.exists():
        current_stored_url = state_file.read_text(encoding="utf-8").strip()
            
    # 2. เงื่อนไขการข้ามการโหลด: URL ตรงกัน และ มีไฟล์ข้อมูลอยู่แล้ว และ ไม่ได้สั่ง force_update

    if (not force_update) and (current_stored_url == urls_key) and data_file.exists():
        print(f"[*] URL matches source_url.txt. Loading from local cache...")
    else:
        # 3. กรณี URL ไม่ซ้ำ หรือต้องการอัปเดต: เริ่มการโหลดใหม่
        print(f"[!] URL mismatch or update required. Fetching new data...")
        frames = []
        target_urls = urls if isinstance(urls, list) else [urls]
        
        for url in target_urls:
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                with ZipFile(BytesIO(response.content)) as zf:
                    # แตกไฟล์แรกที่เจอ (JSON) และโหลดเข้า DataFrame
                    with zf.open(zf.namelist()[0]) as src:
                        frames.append(pd.read_json(src, lines=True))
                print(f"[*] Downloaded: {url.split('/')[-1]}")
            except Exception as e:
                print(f"[!] Error downloading {url}: {e}")
                raise

        # 4. รวมข้อมูลและเขียนทับไฟล์เดิม (Overwrite)
        combined_df = pd.concat(frames, ignore_index=True)
        combined_df.to_json(data_file, orient="records", lines=True)
            
        # 5. เขียนทับ URL ใหม่ลงใน source_url.txt
        state_file.write_text(urls_key, encoding="utf-8")
        print(f"[*] Cache updated and URL tracker overwritten.")

    #โหลดข้อมูลจากไฟล์ที่เตรียมไว้ส่งคืนให้ Pipeline
    return pd.read_json(data_file, lines=True)

def normalize(df):
    """
    Normalize Sysmon/Security log column names into generic representations.
    Uses .get() method to prevent KeyErrors per Task 2.
    """
    try:
        # Date parsing
        df["@timestamp"] = pd.to_datetime(df.get("@timestamp"), utc=True, errors="coerce")
        df = df.dropna(subset=["@timestamp"]).copy()
        
        # Standardize column names with .get() fallbacks to prevent KeyErrors
        df["_process"] = df.get("Image", df.get("NewProcessName", pd.Series(dtype="object"))).fillna("UNKNOWN").astype(str)
        df["_parent"]  = df.get("ParentImage", df.get("ParentProcessName", pd.Series(dtype="object"))).fillna("UNKNOWN").astype(str)
        df["_cmd"]     = df.get("CommandLine", pd.Series(dtype="object")).fillna("UNKNOWN").astype(str)
        df["_host"]    = df.get("Hostname", df.get("Computer", pd.Series(dtype="object"))).fillna("UNKNOWN").astype(str)
        df["_user"]    = df.get("User", pd.Series(dtype="object")).fillna("UNKNOWN").astype(str)
        
        # Additional image and script columns
        df["_image_loaded"]    = df.get("ImageLoaded", pd.Series(dtype="object")).fillna("").astype(str)
        df["_target_image"]    = df.get("TargetImage", pd.Series(dtype="object")).fillna("").astype(str)
        df["_target_filename"] = df.get("TargetFilename", pd.Series(dtype="object")).fillna("").astype(str)
        
        return df
        
    except Exception as e:
        print(f"[!] Error normalizing dataset: {e}")
        raise
