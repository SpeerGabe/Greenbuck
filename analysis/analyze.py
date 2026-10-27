"""
Classifies GreenBuck requests from TLS metadata and measures defense overhead.

Reads exchanges.csv (from extract_exchanges.py or the research database) and the
iterations log (iterations.jsonl from a capture, or iterations.csv exported from
the research database), and writes to out_dir:
  classification.csv  macro-F1, balanced accuracy and accuracy for every
                      cipher x defense x model x feature set, each with a 95%
                      confidence interval from a bootstrap over runs
  confusion.csv       confusion counts for every cipher x defense, Random Forest on all features
  overhead.csv        bytes per run, server response time and phone-measured
                      action time for every cipher x defense, and each one's
                      increase over the same cipher with no defense

Each condition is cross-validated with 5 folds grouped by run, so no run has
requests in both training and test data.

Usage:
  python3 analyze.py exchanges.csv iterations.csv out_dir
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SIZE_FEATURES = ["req_records", "req_bytes", "resp_records", "resp_bytes",
                 "req_packets", "resp_packets", "req_wire_bytes", "resp_wire_bytes"]
# Server timing: how long the server took to answer and to send the answer.
SERVER_TIMING_FEATURES = ["ttfb_ms", "latency_ms", "resp_transfer_ms"]
# Client timing: the pause before each request, set by the app and the test script's pacing.
CLIENT_TIMING_FEATURES = ["gap_before_ms"]
FEATURE_SETS = {
    "size": SIZE_FEATURES,
    "server_timing": SERVER_TIMING_FEATURES,
    "client_timing": CLIENT_TIMING_FEATURES,
    "all": SIZE_FEATURES + SERVER_TIMING_FEATURES + CLIENT_TIMING_FEATURES + ["exchange_ms", "pos_in_conn"],
}
MODELS = {
    "random_forest": lambda: RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                                    random_state=0, n_jobs=2),
    "knn": lambda: make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5)),
}
FOLDS = 5
BOOTSTRAP = 1000
METRIC_NAMES = ["macro_f1", "balanced_accuracy", "accuracy"]


def metrics_from_codes(true, pred, k):
    """macro-F1, balanced accuracy and accuracy from integer class codes.

    Matches scikit-learn: macro-F1 averages over classes present in either
    array, balanced accuracy over classes present in the true labels.
    """
    cm = np.bincount(true * k + pred, minlength=k * k).reshape(k, k)
    tp = np.diag(cm).astype(float)
    actual, predicted = cm.sum(axis=1), cm.sum(axis=0)
    with np.errstate(divide="ignore", invalid="ignore"):
        recall = np.where(actual > 0, tp / actual, 0.0)
        precision = np.where(predicted > 0, tp / predicted, 0.0)
        f1 = np.where(precision + recall > 0, 2 * precision * recall / (precision + recall), 0.0)
    present = (actual > 0) | (predicted > 0)
    return f1[present].mean(), recall[actual > 0].mean(), tp.sum() / cm.sum()


def out_of_fold(df, features, make_model):
    """Predicts every request with a model trained on the other folds' runs."""
    pred = np.empty(len(df), dtype=object)
    x, y, groups = df[features].to_numpy(), df["label"].to_numpy(), df["run_id"].to_numpy()
    for train, test in GroupKFold(n_splits=FOLDS).split(x, y, groups):
        model = make_model()
        model.fit(x[train], y[train])
        pred[test] = model.predict(x[test])
    return pred


def bootstrap_ci(true, pred, groups, k, rng):
    """95% intervals of each metric when whole runs are resampled with replacement."""
    runs = np.unique(groups)
    index_by_run = [np.flatnonzero(groups == run) for run in runs]
    scores = np.empty((BOOTSTRAP, len(METRIC_NAMES)))
    for b in range(BOOTSTRAP):
        idx = np.concatenate([index_by_run[i] for i in rng.integers(0, len(runs), len(runs))])
        scores[b] = metrics_from_codes(true[idx], pred[idx], k)
    return np.percentile(scores, [2.5, 97.5], axis=0)


def classify(exchanges):
    rows, confusion = [], []
    rng = np.random.default_rng(0)
    for (encryption, mitigation), df in exchanges.groupby(["encryption", "mitigation"]):
        df = df.reset_index(drop=True)
        y, groups = df["label"].to_numpy(), df["run_id"].to_numpy()
        labels = sorted(np.unique(y))
        code = {label: i for i, label in enumerate(labels)}
        true = np.array([code[v] for v in y])
        for model_name, make_model in MODELS.items():
            for set_name, features in FEATURE_SETS.items():
                pred = out_of_fold(df, features, make_model)
                pred_codes = np.array([code[v] for v in pred])
                point = metrics_from_codes(true, pred_codes, len(labels))
                low, high = bootstrap_ci(true, pred_codes, groups, len(labels), rng)
                row = {"encryption": encryption, "mitigation": mitigation, "model": model_name,
                       "features": set_name, "runs": len(np.unique(groups)), "requests": len(df),
                       "classes": len(labels), "chance": 1 / len(labels)}
                for i, metric_name in enumerate(METRIC_NAMES):
                    row[metric_name] = point[i]
                    row[f"{metric_name}_low"], row[f"{metric_name}_high"] = low[i], high[i]
                row["sklearn_macro_f1"] = f1_score(y, pred, average="macro", zero_division=0)
                row["sklearn_balanced_accuracy"] = balanced_accuracy_score(y, pred)
                rows.append(row)
                if model_name == "random_forest" and set_name == "all":
                    matrix = confusion_matrix(y, pred, labels=labels)
                    for i, true_label in enumerate(labels):
                        for j, predicted_label in enumerate(labels):
                            confusion.append({"encryption": encryption, "mitigation": mitigation,
                                              "true": true_label, "predicted": predicted_label,
                                              "count": int(matrix[i, j])})
        print(f"  classified {encryption:9s} {mitigation}", flush=True)
    return pd.DataFrame(rows), pd.DataFrame(confusion)


def overhead(exchanges, iterations):
    per_run = (exchanges.assign(bytes=exchanges["req_bytes"] + exchanges["resp_bytes"])
               .groupby(["encryption", "mitigation", "run_id"])["bytes"].sum().reset_index())
    table = per_run.groupby(["encryption", "mitigation"])["bytes"].mean().rename("bytes_per_run").to_frame()
    table["server_response_ms"] = exchanges.groupby(["encryption", "mitigation"])["ttfb_ms"].median()
    runs = exchanges[["run_id", "encryption", "mitigation"]].drop_duplicates()
    actions = iterations.merge(runs, on="run_id")
    table["action_time_ms"] = actions.groupby(["encryption", "mitigation"])["elapsed_ms"].mean()
    table = table.reset_index()

    baseline = table[table["mitigation"] == "none"].set_index("encryption")
    table["bandwidth_overhead_pct"] = 100 * (table["bytes_per_run"]
                                             / table["encryption"].map(baseline["bytes_per_run"]) - 1)
    table["server_response_added_ms"] = (table["server_response_ms"]
                                         - table["encryption"].map(baseline["server_response_ms"]))
    table["action_time_added_ms"] = (table["action_time_ms"]
                                     - table["encryption"].map(baseline["action_time_ms"]))
    return table


def main():
    parser = argparse.ArgumentParser(description="Classify GreenBuck requests and measure overhead.")
    parser.add_argument("exchanges_csv", type=Path)
    parser.add_argument("iterations_jsonl", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    exchanges = pd.read_csv(args.exchanges_csv)
    if args.iterations_jsonl.suffix == ".csv":
        iterations = pd.read_csv(args.iterations_jsonl)
    else:
        with open(args.iterations_jsonl, encoding="utf-8") as f:
            iterations = pd.DataFrame([json.loads(line) for line in f if line.strip()])

    results, confusion = classify(exchanges)
    results.to_csv(args.out_dir / "classification.csv", index=False)
    confusion.to_csv(args.out_dir / "confusion.csv", index=False)
    overhead(exchanges, iterations).to_csv(args.out_dir / "overhead.csv", index=False)
    print(f"wrote results to {args.out_dir}")


if __name__ == "__main__":
    main()
