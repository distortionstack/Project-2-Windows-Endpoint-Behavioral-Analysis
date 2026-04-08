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
    Downloads datasets and extracts JSON if URLs change or force_update=True.
    Reads from data/raw/current_dataset.json otherwise to skip download.
    Returns: pandas DataFrame
    """
    raw_dir = Path("data/raw")
    out_dir = Path("outputs")
    
    # Ensure professional project structure exists
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    state_file = raw_dir / "source_url.txt"
    data_file = raw_dir / "current_dataset.json"
    
    # Handle single string gracefully
    if isinstance(urls, str):
        urls = [urls]
        
    urls_key = ",".join(urls)
    
    # State Tracking: Read current stored URL
    current_url_key = None
    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                current_url_key = f.read().strip()
        except Exception as e:
            print(f"[!] Warning: Could not read {state_file}: {e}")
            
    # Conditional Download Logic
    if (not force_update) and (current_url_key == urls_key) and data_file.exists():
        print(f"[*] Data already up-to-date. Skipping download.")
    else:
        frames = []
        for url in urls:
            print(f"[*] Downloading dataset from: {url}")
            try:
                # Download the zip
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                # Extract JSON from memory
                with ZipFile(BytesIO(response.content)) as zf:
                    extracted_name = zf.namelist()[0]
                    with zf.open(extracted_name) as src:
                        df_part = pd.read_json(src, lines=True)
                        frames.append(df_part)
                        
            except Exception as e:
                print(f"[!] Error during download/extraction of {url}: {e}")
                raise
                
        # Combine dataframes
        print("[*] Combining datasets and saving to cache...")
        combined_df = pd.concat(frames, ignore_index=True)
        # Overwrite current_dataset.json
        combined_df.to_json(data_file, orient="records", lines=True)
            
        # State Update: save the new completed URL string
        with open(state_file, "w", encoding="utf-8") as f:
            f.write(urls_key)
                
        print(f"[*] Successfully extracted and combined dataset to {data_file}")
            
    # Data Loading
    try:
        print(f"[*] Loading dataset into Pandas DataFrame...")
        # read_json with lines=True as instructed
        df = pd.read_json(data_file, lines=True)
        return df
    except Exception as e:
        print(f"[!] Error reading JSON file into DataFrame: {e}")
        raise


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
