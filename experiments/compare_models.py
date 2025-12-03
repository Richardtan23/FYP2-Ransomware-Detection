# src/compare_models.py
#
# Compare:
#   STATIC:   RandomForest vs XGBoost
#   BEHAVIOR: CatBoost vs LightGBM
#
# Uses:
#   data_processed/static_baseline.parquet
#   data_processed/behav_baseline.parquet
#   models/optimized/*.joblib / *.cbm / feature_names / thresholds

from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

from catboost import CatBoostClassifier  # for behavioural CatBoost model


# =========================================================
# CONFIG – ADJUST LABEL COLUMN NAMES IF NEEDED
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

STATIC_DATA_PATH = PROJECT_ROOT / "data_processed" / "static_baseline.parquet"
BEHAV_DATA_PATH = PROJECT_ROOT / "data_processed" / "behav_val.parquet"

# For static dataset: "Benign" = 1 means safe, so malicious = 1 - Benign
STATIC_LABEL_COL = "Benign"
STATIC_LABEL_IS_BENIGN = True  # important

# For behavioural dataset – we'll guess for now and adjust later if needed
BEHAV_LABEL_COL = "label"       # change later if your behav parquet uses "Benign"
BEHAV_LABEL_IS_BENIGN = False   # set to True if it also uses "Benign"
BEHAV_LABEL_FROM_FAMILY = True  # we will derive y from Family column



MODELS_OPT = PROJECT_ROOT / "models" / "optimized"

# Static models & metadata
STATIC_RF_MODEL_PATH = MODELS_OPT / "static_rf_tuned.joblib"
STATIC_RF_FEATS_PATH = MODELS_OPT / "static_rf_feature_names.joblib"
STATIC_RF_THR_PATH   = MODELS_OPT / "static_rf_threshold.json"

STATIC_XGB_MODEL_PATH = MODELS_OPT / "static_xgb_tuned.joblib"
STATIC_XGB_FEATS_PATH = MODELS_OPT / "static_xgb_feature_names.joblib"
STATIC_XGB_THR_PATH   = MODELS_OPT / "static_xgb_threshold.json"

# Behavioural models & metadata
BEHAV_CATBOOST_PATH = MODELS_OPT / "behav_catboost_tuned.cbm"
BEHAV_SCHEMA_PATH   = MODELS_OPT / "behav_feature_names.json"  # has use_cols + cat_cols
BEHAV_LGBM_PATH     = MODELS_OPT / "behav_lgbm.joblib"
BEHAV_THR_PATH      = MODELS_OPT / "behav_threshold.json"


# =========================================================
# UTILITIES
# =========================================================

def load_threshold(path: Path, default: float = 0.5) -> float:
    """
    Load tuned threshold from a JSON file.
    Tries several common keys, falls back to default if not found.
    """
    try:
        with open(path, "r") as f:
            obj = json.load(f)
        thr = float(
            obj.get(
                "best_threshold_malicious",
                obj.get("best_threshold", obj.get("threshold", default)),
            )
        )
        return thr
    except Exception:
        return default


def print_metrics_block(name: str, y_true, y_prob, y_pred):
    """
    Print a nice summary of metrics for one model.
    Assumes binary classification with positive class = 1 (malicious).
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    try:
        auc = roc_auc_score(y_true, y_prob)
    except ValueError:
        auc = float("nan")

    print(f"\n=== {name} ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-score : {f1:.4f}")
    print(f"ROC-AUC  : {auc:.4f}")


# =========================================================
# STATIC MODELS: RF vs XGB
# =========================================================

def compare_static_models():
    print("\n" + "=" * 60)
    print(" STATIC MODELS: RandomForest vs XGBoost")
    print("=" * 60)

    # Load dataset
    if not STATIC_DATA_PATH.exists():
        print(f"[!] Static baseline dataset not found at {STATIC_DATA_PATH}")
        return

    df = pd.read_parquet(STATIC_DATA_PATH)
    if STATIC_LABEL_COL not in df.columns:
        raise KeyError(
            f"Static label column '{STATIC_LABEL_COL}' not found in {STATIC_DATA_PATH}. "
            "Please update STATIC_LABEL_COL in compare_models.py."
        )

    # Build target: we want y = 1 for malicious, 0 for benign
    if STATIC_LABEL_IS_BENIGN:
    # Benign=1 -> y=0 (benign), Benign=0 -> y=1 (malicious)
        y = (1 - df[STATIC_LABEL_COL].astype(int)).values
    else:
        y = df[STATIC_LABEL_COL].astype(int).values

    X = df.drop(columns=[STATIC_LABEL_COL])


    # ----- RandomForest -----
    rf_model = joblib.load(STATIC_RF_MODEL_PATH)
    rf_feats = joblib.load(STATIC_RF_FEATS_PATH)
    rf_thr = load_threshold(STATIC_RF_THR_PATH, default=0.5)

    X_rf = X.copy()
    # ensure all required columns exist
    for c in rf_feats:
        if c not in X_rf.columns:
            X_rf[c] = 0.0
    X_rf = X_rf[rf_feats].copy()

    rf_prob = rf_model.predict_proba(X_rf)[:, 1]  # P(malicious)
    rf_pred = (rf_prob >= rf_thr).astype(int)

    print_metrics_block("Static RandomForest (tuned)", y, rf_prob, rf_pred)
    print(f"Decision threshold used: {rf_thr:.3f}")

    # ----- XGBoost -----
    xgb_model = joblib.load(STATIC_XGB_MODEL_PATH)
    xgb_feats = joblib.load(STATIC_XGB_FEATS_PATH)
    xgb_thr = load_threshold(STATIC_XGB_THR_PATH, default=0.5)

    X_xgb = X.copy()
    for c in xgb_feats:
        if c not in X_xgb.columns:
            X_xgb[c] = 0.0
    X_xgb = X_xgb[xgb_feats].copy()

    xgb_prob = xgb_model.predict_proba(X_xgb)[:, 1]
    xgb_pred = (xgb_prob >= xgb_thr).astype(int)

    print_metrics_block("Static XGBoost (tuned)", y, xgb_prob, xgb_pred)
    print(f"Decision threshold used: {xgb_thr:.3f}")


# =========================================================
# BEHAVIOURAL MODELS: CatBoost vs LightGBM
# =========================================================

def load_behav_schema():
    """
    Load behavioural schema (use_cols, cat_cols) from behav_feature_names.json.
    """
    with open(BEHAV_SCHEMA_PATH, "r") as f:
        obj = json.load(f)
    use_cols = obj["use_cols"]
    cat_cols = obj.get("cat_cols", [])
    return use_cols, cat_cols


def compare_behavioural_models():
    print("\n" + "=" * 60)
    print(" BEHAVIOURAL MODELS: CatBoost vs LightGBM")
    print("=" * 60)

    if not BEHAV_DATA_PATH.exists():
        print(f"[!] Behavioural baseline dataset not found at {BEHAV_DATA_PATH}")
        return

    df = pd.read_parquet(BEHAV_DATA_PATH)

        # ---------- Build y from the saved label column ----------
    if "label" not in df.columns:
        raise KeyError(
            f"Expected 'label' column in {BEHAV_DATA_PATH}. "
            "Please export behav_val.parquet from your training notebook."
        )

    y = df["label"].astype(int).values
    X = df.drop(columns=["label"])


    # Load schema: which columns to use, which are categorical
    use_cols, cat_cols = load_behav_schema()
    thr = load_threshold(BEHAV_THR_PATH, default=0.5)

    # Align features
    X_behav = X.copy()
    for c in use_cols:
        if c not in X_behav.columns:
            X_behav[c] = 0.0
    X_behav = X_behav[use_cols].copy()

    # ---------- CatBoost (tuned) ----------
    # For CatBoost, categorical features must be strings or ints
    X_cat = X_behav.copy()
    for c in cat_cols:
        if c in X_cat.columns:
            X_cat[c] = X_cat[c].astype(str)

    cat_model = CatBoostClassifier()
    cat_model.load_model(str(BEHAV_CATBOOST_PATH))

    cat_prob = cat_model.predict_proba(X_cat)[:, 1]
    cat_pred = (cat_prob >= thr).astype(int)

    print_metrics_block("Behavioural CatBoost (tuned)", y, cat_prob, cat_pred)
    print(f"Decision threshold used: {thr:.3f}")

    # ---------- LightGBM (tuned) ----------
    lgbm_model = joblib.load(BEHAV_LGBM_PATH)

    X_lgbm = X_behav.copy()
    for c in cat_cols:
        if c in X_lgbm.columns:
            X_lgbm[c] = X_lgbm[c].astype("category")

    lgbm_prob = lgbm_model.predict_proba(X_lgbm)[:, 1]
    lgbm_pred = (lgbm_prob >= thr).astype(int)

    print_metrics_block("Behavioural LightGBM (tuned)", y, lgbm_prob, lgbm_pred)
    print(f"Decision threshold used: {thr:.3f}")




# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    print(">>> Comparing Static and Behavioural Models <<<")
    compare_static_models()
    compare_behavioural_models()
    print("\nDone.")
