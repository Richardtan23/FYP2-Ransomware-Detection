# src/static_model.py
import os, json, joblib
import numpy as np
import pandas as pd

from typing import Tuple, List
from .explain_utils import friendly_explanations

ROOT = os.path.dirname(os.path.dirname(__file__))
OPT = os.path.join(ROOT, "models", "optimized")

STATIC_MODEL_PATH = os.path.join(OPT, "static_xgb_tuned.joblib")
STATIC_FEATS_PATH = os.path.join(OPT, "static_xgb_feature_names.joblib")  # or .json depending on your file
STATIC_THR_PATH   = os.path.join(OPT, "static_xgb_threshold.json")

_model = None
_feats = None
_thr   = None

def _load_once():
    global _model, _feats, _thr
    if _model is None:
        _model = joblib.load(STATIC_MODEL_PATH)
        _feats = joblib.load(STATIC_FEATS_PATH) if STATIC_FEATS_PATH.endswith(".joblib") \
                 else json.load(open(STATIC_FEATS_PATH))
        try:
            with open(STATIC_THR_PATH) as f:
                tjson = json.load(f)
            _thr = float(tjson.get("best_threshold", tjson.get("threshold", 0.5)))
        except Exception:
            _thr = 0.5
    return _model, _feats, _thr

def _ensure_order(X: pd.DataFrame, feats: list) -> pd.DataFrame:
    for c in feats:
        if c not in X.columns:
            X[c] = 0.0
    return X[feats]

def _top_features(model, feats: list, k: int = 5) -> List[tuple]:
    # pipeline-safe try: if model is pipeline, last step may have feature_importances_
    est = model[-1] if hasattr(model, "__getitem__") else model
    fi = getattr(est, "feature_importances_", None)
    if fi is None:
        return []
    pairs = sorted(zip(feats, fi), key=lambda t: t[1], reverse=True)[:k]
    return [(f, float(v)) for f, v in pairs]

def predict_static(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, float, list]:
    """
    Returns: (probs, preds, threshold_used, reasons_list)
    Expects a row-per-file static features dataframe.
    """
    model, feats, thr = _load_once()
    X = _ensure_order(df.copy(), feats)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= thr).astype(int)
    top = _top_features(model, feats, k=5)
    reasons = friendly_explanations(top[:3])
    return probs, preds, thr, reasons

def get_static_feature_names() -> list:
    """
    Expose the ordered list of static feature names that the XGBoost model expects.
    """
    _, feats, _ = _load_once()
    return feats
