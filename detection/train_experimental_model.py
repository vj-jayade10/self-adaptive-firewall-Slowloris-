import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = PROJECT_ROOT / "data" / "normal_baseline_experimental_20261031.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "trained"
MODEL_FILE = MODEL_DIR / "isolation_forest_experimental_20261031.pkl"

FEATURES = [
    "packets_per_second",
    "bytes_per_second",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports",
    "new_tcp_connections",
    "active_tcp_connections",
    "long_lived_tcp_connections",
    "mean_connection_age_seconds",
    "max_connection_age_seconds",
]


def main():
    print("===================================")
    print("   ISOLATION FOREST MODEL V2")
    print("===================================\n")

    if not DATA_FILE.exists():
        sys.exit(f"ERROR: Baseline not found: {DATA_FILE}")

    if MODEL_FILE.exists():
        sys.exit(
            f"ERROR: {MODEL_FILE} already exists. "
            "Refusing to overwrite it."
        )

    df = pd.read_csv(DATA_FILE)

    missing = [feature for feature in FEATURES if feature not in df.columns]
    if missing:
        sys.exit(f"ERROR: Missing feature columns: {missing}")

    X = df[FEATURES].copy()

    for column in FEATURES:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    if X.isna().any().any():
        sys.exit("ERROR: Dataset contains missing or non-numeric values.")

    if len(X) < 50:
        sys.exit(f"ERROR: Only {len(X)} samples. At least 50 are required.")

    print(f"Training samples: {len(X)}")
    print(f"Features: {len(FEATURES)}")
    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)

    print("\nModel trained successfully.")
    print(f"Saved new model to: {MODEL_FILE}")
    print("Original isolation_forest.pkl was not modified.")


if __name__ == "__main__":
    main()
