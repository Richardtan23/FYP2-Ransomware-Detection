from __future__ import annotations
import pandas as pd
import numpy as np

# --- header typos that appear in ugransom.csv ---
RENAME_MAP = {
    "Protcol": "Protocol",
    "SeddAddress": "SeedAddress",
    "IPaddress": "IPAddress",   # not used, but normalized
}

# --- feature engineering used in your notebooks ---
WELL_KNOWN_PORTS = {80, 443, 53, 25, 110, 143, 995, 993}

def bucket_port(p):
    if pd.isna(p):
        return -1
    try:
        p = int(p)
    except Exception:
        return -1
    if p in WELL_KNOWN_PORTS:
        return p
    if p < 1024:
        return 1000
    if p < 10000:
        return 10000
    return 65535

def normalize_headers(df: pd.DataFrame) -> pd.DataFrame:
    return df.rename(columns=RENAME_MAP)

def build_behav_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build the SAME engineered columns you used when training CatBoost:
    - ProtoFlag (Protocol + '_' + Flag)
    - PortBucket (binned Port)
    - has_BTC / has_USD
    - log1p on BTC / USD / Netflow_Bytes
    - numeric coercion for Time, Clusters, Port
    """
    df = normalize_headers(df.copy())

    # Create target if present (not used for inference)
    if "Family" in df.columns:
        df["is_wannacry"] = (df["Family"].astype(str) == "WannaCry").astype(int)

    # ProtoFlag
    for c in ["Protocol", "Flag"]:
        if c not in df.columns:
            df[c] = ""
    df["ProtoFlag"] = df["Protocol"].astype(str) + "_" + df["Flag"].astype(str)

    # Port bucket
    if "Port" not in df.columns:
        df["Port"] = np.nan
    df["PortBucket"] = df["Port"].apply(bucket_port)

    # Threats
    if "Threats" not in df.columns:
        df["Threats"] = ""

    # has_BTC / has_USD
    for c in ["BTC", "USD"]:
        if c not in df.columns:
            df[c] = 0
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    df["has_BTC"] = (df["BTC"] > 0).astype(int)
    df["has_USD"] = (df["USD"] > 0).astype(int)

    # log1p numeric skew
    for c in ["BTC", "USD", "Netflow_Bytes"]:
        if c in df.columns:
            df[c] = np.log1p(pd.to_numeric(df[c], errors="coerce").fillna(0))

    # coerce some numerics
    for c in ["Time", "Clusters", "Port"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    return df
