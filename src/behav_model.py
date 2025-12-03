# src/behav_model.py
#
# Behavioural risk model (rule-based, Sysmon-based)
#
# This version is aligned with the new behavioural pipeline:
#   Sysmon XML -> event-level CSV -> aggregated features CSV
#
# It keeps the SAME public interface as the previous LightGBM-based version:
#   predict_behav(df) -> (probs, preds, threshold_used, reasons_list)
#
# so app.py and the fusion engine do not need to change.

from typing import Tuple, List
import numpy as np
import pandas as pd

# Tunable threshold for "malicious" based on behavioural score
BEHAV_THRESHOLD = 0.6


def _compute_behav_score(row: pd.Series) -> Tuple[float, List[str]]:
    total = float(row.get("total_events", 0) or 0)
    n_proc = float(row.get("n_proc_create", 0) or 0)
    n_file = float(row.get("n_file_create", 0) or 0)
    n_net = float(row.get("n_net_conn", 0) or 0)

    ratio_proc = float(row.get("ratio_proc_create", 0) or (n_proc / total if total > 0 else 0))
    ratio_file = float(row.get("ratio_file_create", 0) or (n_file / total if total > 0 else 0))
    ratio_net = float(row.get("ratio_net_conn", 0) or (n_net / total if total > 0 else 0))

    score = 0.0
    reasons: List[str] = []

    # 1) Massive file activity → strong ransomware signal
    if n_file > 1000 or ratio_file > 0.5:
        score += 0.6
        reasons.append(
            "Unusually high proportion of file-creation events, "
            "consistent with mass file modification or encryption behaviour."
        )

    # 2) Network activity → possible propagation / C2
    if n_net > 5 or ratio_net > 0.02:
        score += 0.2
        reasons.append(
            "Network connection events detected, suggesting potential "
            "propagation or command-and-control communication."
        )

    # 3) Process creation → process spawning / injection
    if n_proc > 10 or ratio_proc > 0.02:
        score += 0.2
        reasons.append(
            "Multiple process creation events observed, which may indicate "
            "process spawning or code injection behaviour."
        )

    # Clamp score to [0, 1]
    score = max(0.0, min(score, 1.0))

    if not reasons:
        reasons.append(
            "Behavioural activity appears within normal ranges typically observed in benign software."
        )

    return score, reasons


def predict_behav(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, float, List[str]]:
    if df is None or df.empty:
        # No behavioural data — return zeros and a neutral explanation
        probs = np.array([0.0], dtype=float)
        preds = np.array([0], dtype=int)
        reasons = ["No behavioural events available for analysis."]
        return probs, preds, BEHAV_THRESHOLD, reasons

    # Compute score per row
    probs_list = []
    reasons_for_first: List[str] = []

    for idx, row in df.iterrows():
        score, reasons = _compute_behav_score(row)
        probs_list.append(score)
        # For simplicity, keep reasons from the first row only
        if idx == 0:
            reasons_for_first = reasons

    probs = np.array(probs_list, dtype=float)
    preds = (probs >= BEHAV_THRESHOLD).astype(int)

    return probs, preds, BEHAV_THRESHOLD, reasons_for_first
