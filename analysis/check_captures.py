"""
Checks a GreenBuck capture set before hand-off or analysis.

Reads markers.jsonl and the pcaps in a capture data directory and, when given,
a CSV export of the timing_log table. Prints clean-run counts per configuration
and lists every run that needs a second look. Exits 1 if any run is flagged.

Usage:
  python3 check_captures.py capture/data
  python3 check_captures.py capture/data --timing-log timing_log.csv
"""

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

# Requests each scheduled action sends, by schedule code. Under batching the
# dashboard's balance and history requests travel as one /batch request.
REQUESTS_PER_ACTION = {
    "default": {"L": 3, "H": 4, "T": 6, "B": 5, "R": 1, "O": 4},
    "batching": {"L": 2, "H": 3, "T": 5, "B": 3, "R": 1, "O": 3},
}


def expected_requests(marker):
    table = REQUESTS_PER_ACTION["batching" if marker["mitigation"] == "batching" else "default"]
    return sum(table[code] for code in marker["schedule"])


def load_markers(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_timing_log(path):
    rows_by_run = collections.defaultdict(list)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows_by_run[row["run_id"]].append(row)
    return rows_by_run


def check_run(marker, data_dir, rows_by_run):
    problems = []
    scheduled = len(marker.get("schedule", ""))
    if not marker.get("test_passed"):
        problems.append("integration test did not pass")
    if marker.get("iterations_failed", 0):
        problems.append(f"{marker['iterations_failed']} iterations failed")
    if marker.get("iterations_reported") != scheduled:
        problems.append(f"{marker.get('iterations_reported')} of {scheduled} iterations reported")
    if marker.get("packet_count", 0) == 0:
        problems.append("pcap has no packets")
    if not (data_dir / marker["pcap_filename"]).exists():
        problems.append("pcap file missing")

    if rows_by_run is not None:
        rows = rows_by_run.get(marker["run_id"], [])
        if not rows:
            problems.append("no timing_log rows")
        else:
            expected = expected_requests(marker)
            if len(rows) != expected:
                problems.append(f"{len(rows)} timing_log rows, expected {expected}")
            labels = {(r["encryption_mode"], r["mitigation_state"]) for r in rows}
            if labels != {(marker["encryption"], marker["mitigation"])}:
                problems.append(f"timing_log labels {sorted(labels)} don't match the marker")
            errors = sum(1 for r in rows if int(r["status_code"]) >= 400)
            if errors:
                problems.append(f"{errors} error responses (status >= 400)")
    return problems


def main():
    parser = argparse.ArgumentParser(description="Check a GreenBuck capture set.")
    parser.add_argument("data_dir", type=Path, help="Directory holding markers.jsonl and the pcaps")
    parser.add_argument("--timing-log", type=Path, help="CSV export of the timing_log table")
    args = parser.parse_args()

    markers = load_markers(args.data_dir / "markers.jsonl")
    rows_by_run = load_timing_log(args.timing_log) if args.timing_log else None

    run_keys = collections.Counter(
        (m["platform"], m["encryption"], m["mitigation"], m["run_number"]) for m in markers
    )
    per_config = collections.defaultdict(lambda: [0, 0])
    flagged = []
    clean_run_ids = set()

    for m in markers:
        problems = check_run(m, args.data_dir, rows_by_run)
        if run_keys[(m["platform"], m["encryption"], m["mitigation"], m["run_number"])] > 1:
            problems.append("run number used more than once in this configuration")
        config = (m["platform"], m["encryption"], m["mitigation"])
        per_config[config][0] += 1
        if problems:
            flagged.append((m, problems))
        else:
            per_config[config][1] += 1
            clean_run_ids.add(m["run_id"])

    print(f"{'platform':<9} {'encryption':<11} {'mitigation':<15} {'runs':>5} {'clean':>6}")
    for (platform, encryption, mitigation), (runs, clean) in sorted(per_config.items()):
        print(f"{platform:<9} {encryption:<11} {mitigation:<15} {runs:>5} {clean:>6}")
    print(f"\n{len(markers)} runs in {len(per_config)} configurations, {len(flagged)} flagged")

    marked_pcaps = {m["pcap_filename"] for m in markers}
    orphans = sorted(p.name for p in args.data_dir.glob("*.pcap") if p.name not in marked_pcaps)
    if orphans:
        print(f"\npcaps with no marker ({len(orphans)}): {', '.join(orphans)}")

    if rows_by_run is not None:
        marker_ids = {m["run_id"] for m in markers}
        unmatched = {run_id: len(rows) for run_id, rows in rows_by_run.items() if run_id not in marker_ids}
        if unmatched:
            total = sum(unmatched.values())
            print(f"\ntiming_log rows from runs with no marker (manual or test traffic, leave out of analysis): "
                  f"{total} rows in {len(unmatched)} run IDs")
        labels = collections.Counter(
            r["action_type"] for run_id in clean_run_ids for r in rows_by_run[run_id]
        )
        if labels:
            print("\nlabeled requests in clean runs: "
                  + ", ".join(f"{action} {count}" for action, count in labels.most_common()))

    if flagged:
        print("\nflagged runs:")
        for m, problems in flagged:
            print(f"  {m['pcap_filename']} ({m['run_id']})")
            for problem in problems:
                print(f"    - {problem}")
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
