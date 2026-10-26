"""Train and load an advisory Isolation Forest from known-benign traffic windows."""

from __future__ import annotations

import argparse
import csv
import os
import tempfile
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_FORMAT = "sentinel-isolation-forest-v1"
FEATURE_NAMES = (
    "requests",
    "unique_sources",
    "unique_routes",
    "blocked_ratio",
    "suspicious_events",
    "source_entropy",
)


def synthetic_benign_baseline(rows: int = 600, seed: int = 1649) -> np.ndarray:
    """Create explicitly synthetic demo training data; never presented as real traffic."""
    rng = np.random.default_rng(seed)
    requests = rng.poisson(7, rows) + 1
    unique_sources = np.minimum(requests, rng.poisson(0.8, rows) + 1)
    unique_routes = np.minimum(requests, rng.poisson(1.5, rows) + 1)
    blocked_ratio = np.clip(rng.beta(0.5, 35, rows), 0, 0.25)
    suspicious_events = rng.poisson(0.02, rows)
    source_entropy = np.where(
        unique_sources > 1,
        rng.uniform(0.1, 1.0, rows) * np.log(unique_sources),
        0.0,
    )
    return np.column_stack((requests, unique_sources, unique_routes, blocked_ratio, suspicious_events, source_entropy))


def _load_csv(path: Path) -> np.ndarray:
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = [name for name in FEATURE_NAMES if name not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"Baseline CSV is missing feature columns: {', '.join(missing)}")
        try:
            rows = [[float(row[name]) for name in FEATURE_NAMES] for row in reader]
        except (TypeError, ValueError) as error:
            raise ValueError(f"Baseline CSV contains a missing or non-numeric feature: {error}") from error
    if len(rows) < 100:
        raise ValueError("Supply at least 100 known-benign time-window rows for a useful baseline.")
    data = np.asarray(rows, dtype=np.float64)
    if not np.isfinite(data).all() or (data < 0).any():
        raise ValueError("Baseline features must be finite, non-negative numbers.")
    if float(np.std(data, axis=0).sum()) == 0:
        raise ValueError("Baseline features contain no variation; collect more representative benign windows.")
    return data


def train_model(data: np.ndarray, *, contamination: float = 0.02, source: str = "operator-baseline") -> dict[str, Any]:
    matrix = np.asarray(data, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES) or matrix.shape[0] < 100:
        raise ValueError(f"Training data must have at least 100 rows and {len(FEATURE_NAMES)} ordered features.")
    if not np.isfinite(matrix).all() or (matrix < 0).any():
        raise ValueError("Training features must be finite and non-negative.")
    if float(np.std(matrix, axis=0).sum()) == 0:
        raise ValueError("Training features contain no variation; collect more representative benign windows.")
    if not 0 < contamination < 0.5:
        raise ValueError("contamination must be greater than 0 and less than 0.5")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=1649,
        n_jobs=1,
    )
    model.fit(matrix)
    return {
        "format": MODEL_FORMAT,
        "features": list(FEATURE_NAMES),
        "model": model,
        "source": source,
        "trained_rows": int(matrix.shape[0]),
        "contamination": contamination,
    }


def save_model(bundle: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
            temporary_name = temporary.name
        joblib.dump(bundle, temporary_name)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def load_model(path: str | Path) -> dict[str, Any] | None:
    model_path = Path(path)
    if not model_path.exists():
        return None
    # Joblib/pickle files must only come from a trusted, controlled path.
    bundle = joblib.load(model_path)
    if not isinstance(bundle, dict) or bundle.get("format") != MODEL_FORMAT or bundle.get("features") != list(FEATURE_NAMES):
        raise ValueError("Unsupported or invalid Sentinel anomaly model.")
    if not hasattr(bundle.get("model"), "decision_function"):
        raise ValueError("Anomaly model does not provide a scoring function.")
    return bundle


def score_window(bundle: dict[str, Any], features: dict[str, float]) -> dict[str, Any]:
    vector = np.asarray([[float(features[name]) for name in FEATURE_NAMES]], dtype=np.float64)
    score = float(bundle["model"].decision_function(vector)[0])
    prediction = int(bundle["model"].predict(vector)[0])
    return {
        "score": score,
        "anomaly": prediction == -1,
        "model_source": str(bundle.get("source", "unknown")),
        "model_format": MODEL_FORMAT,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a Sentinel advisory anomaly model from known-benign HTTP window features.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--baseline", type=Path, help="CSV exported from a reviewed benign deployment baseline.")
    source.add_argument("--demo", action="store_true", help="Train on deterministic synthetic demo data; not suitable for deployment.")
    parser.add_argument("--output", type=Path, default=Path("instance/anomaly-model.joblib"))
    parser.add_argument("--contamination", type=float, default=0.02, help="Expected outlier fraction in training baseline (0 < x < 0.5).")
    args = parser.parse_args()
    if not 0 < args.contamination < 0.5:
        parser.error("--contamination must be greater than 0 and less than 0.5")

    try:
        source_name = "synthetic-demo" if args.demo else "operator-known-benign-csv"
        matrix = synthetic_benign_baseline() if args.demo else _load_csv(args.baseline)
        bundle = train_model(matrix, contamination=args.contamination, source=source_name)
        save_model(bundle, args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Saved {MODEL_FORMAT} model: rows={bundle['trained_rows']} source={source_name} output={args.output}")
    if args.demo:
        print("WARNING: This synthetic demo model is illustrative only; collect and review benign baseline windows before operational use.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
