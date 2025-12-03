import pandas as pd
from pathlib import Path

def aggregate_behavior_csv(input_csv: str, output_csv: str, sample_id: str = "sample_1"):
    df = pd.read_csv(input_csv)

    # Basic safety check
    if df.empty:
        print("[!] Input CSV is empty, nothing to aggregate.")
        return

    # Total events
    total_events = len(df)

    # Simple counts
    n_proc_create = df["is_process_create"].sum()
    n_file_create = df["is_file_create"].sum()
    n_net_conn = df["is_network_conn"].sum()

    # Ratios (avoid divide by zero)
    def safe_ratio(n):
        return n / total_events if total_events > 0 else 0

    features = {
        "sample_id": sample_id,
        "total_events": total_events,
        "n_proc_create": int(n_proc_create),
        "n_file_create": int(n_file_create),
        "n_net_conn": int(n_net_conn),
        "ratio_proc_create": safe_ratio(n_proc_create),
        "ratio_file_create": safe_ratio(n_file_create),
        "ratio_net_conn": safe_ratio(n_net_conn),
    }

    out_path = Path(output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    out_df = pd.DataFrame([features])
    out_df.to_csv(out_path, index=False)

    print(f"[+] Aggregated features written to {out_path}")
    print(out_df)


if __name__ == "__main__":
    input_csv = r"C:\Users\richa\OneDrive\Documents\FYP2\datasets\behavioral\behavior_output.csv"
    output_csv = r"C:\Users\richa\OneDrive\Documents\FYP2\datasets\behavioral\behavior_features_agg.csv"

    aggregate_behavior_csv(input_csv, output_csv, sample_id="wannacry_run_1")
