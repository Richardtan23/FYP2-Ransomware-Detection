from __future__ import annotations
from pathlib import Path
import pandas as pd
from datetime import datetime

LOG_PATH = Path("data_processed/prediction_log.csv")

def append_log(model_name: str, threshold: float, proba: float, pred: int, n_rows: int, note: str = ""):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "model": model_name,
        "threshold": float(threshold),
        "probability": float(proba),
        "prediction": int(pred),
        "rows": int(n_rows),
        "note": note,
    }
    if LOG_PATH.exists():
        df = pd.read_csv(LOG_PATH)
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    else:
        df = pd.DataFrame([row])
    df.to_csv(LOG_PATH, index=False)
