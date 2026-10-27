"""
Builds the GreenBuck research database from a capture hand-off.

Inputs: the capture data directory (markers.jsonl, iterations.jsonl,
batch_log.txt) and exchanges.csv from extract_exchanges.py.
Outputs, in out_dir:
  greenbuck_research.sqlite   runs, iterations, batch_log, exchanges, and an empty timing_log
  csv/*.csv                   the same tables as CSV
  postgres_load.sql           creates the tables in Postgres and loads the CSVs (run with psql from out_dir)

Usage:
  python3 build_research_db.py capture/data exchanges.csv out_dir
"""

import argparse
import csv
import json
import re
import sqlite3
from pathlib import Path

RUN_COLUMNS = [
    ("run_id", "TEXT PRIMARY KEY"), ("platform", "TEXT"), ("encryption", "TEXT"), ("mitigation", "TEXT"),
    ("run_number", "INTEGER"), ("start_time", "TIMESTAMPTZ"), ("end_time", "TIMESTAMPTZ"),
    ("pcap_filename", "TEXT"), ("test_passed", "BOOLEAN"), ("packet_count", "INTEGER"),
    ("seed_sha", "TEXT"), ("schedule", "TEXT"), ("schedule_seed", "BIGINT"), ("think_ms", "INTEGER"),
    ("iterations_reported", "INTEGER"), ("iterations_ok", "INTEGER"), ("iterations_failed", "INTEGER"),
    ("mix_json", "TEXT"),
]
ITERATION_COLUMNS = [
    ("run_id", "TEXT REFERENCES runs(run_id)"), ("i", "INTEGER"), ("action", "TEXT"), ("ok", "BOOLEAN"),
    ("error", "TEXT"), ("device_start", "TIMESTAMP"), ("elapsed_ms", "INTEGER"),
]
BATCH_LOG_COLUMNS = [
    ("logged_at", "TIMESTAMP"), ("encryption", "TEXT"), ("mitigation", "TEXT"), ("run_number", "INTEGER"),
    ("status", "TEXT"), ("detail", "TEXT"),
]
EXCHANGE_TYPES = {
    "run_id": "TEXT REFERENCES runs(run_id)", "pcap_filename": "TEXT", "encryption": "TEXT",
    "mitigation": "TEXT", "run_number": "INTEGER", "iteration": "INTEGER", "action": "TEXT", "label": "TEXT",
    "conn_index": "INTEGER", "client_port": "INTEGER", "pos_in_conn": "INTEGER",
    "t_req_start_s": "DOUBLE PRECISION", "ttfb_ms": "DOUBLE PRECISION", "latency_ms": "DOUBLE PRECISION",
    "resp_transfer_ms": "DOUBLE PRECISION", "exchange_ms": "DOUBLE PRECISION",
    "gap_before_ms": "DOUBLE PRECISION",
}
TIMING_LOG_COLUMNS = [
    ("id", "INTEGER"), ("request_id", "TEXT"), ("run_id", "TEXT"), ("action_type", "TEXT"), ("platform", "TEXT"),
    ("encryption_mode", "TEXT"), ("mitigation_state", "TEXT"), ("receive_time", "TIMESTAMPTZ"),
    ("response_sent_time", "TIMESTAMPTZ"), ("duration_ms", "NUMERIC(10,3)"), ("cpu_utilization", "NUMERIC(5,2)"),
    ("endpoint", "TEXT"), ("status_code", "INTEGER"), ("batch_actions", "TEXT"),
]
BATCH_LOG_LINE = re.compile(r"^(\S+ \S+) (\S+) (\S+) run (\d+): (\S+)(?: (.*))?$")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_rows(markers):
    for m in markers:
        row = {name: m.get(name) for name, _ in RUN_COLUMNS if name != "mix_json"}
        row["mix_json"] = json.dumps(m.get("mix"), sort_keys=True)
        yield row


def iteration_rows(iterations):
    for it in iterations:
        yield {name: it.get(name) for name, _ in ITERATION_COLUMNS}


def batch_log_rows(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = BATCH_LOG_LINE.match(line.strip())
            if match:
                logged_at, encryption, mitigation, run_number, status, detail = match.groups()
                yield {"logged_at": logged_at, "encryption": encryption, "mitigation": mitigation,
                       "run_number": int(run_number), "status": status.rstrip(":"), "detail": detail}


def exchange_columns(header):
    return [("exchange_id", "INTEGER PRIMARY KEY")] + [(name, EXCHANGE_TYPES.get(name, "INTEGER"))
                                                       for name in header]


def exchange_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames
        rows = [{"exchange_id": n, **row} for n, row in enumerate(reader, 1)]
    return header, rows


def sqlite_type(pg_type):
    base = pg_type.split()[0]
    if base in ("INTEGER", "BIGINT", "BOOLEAN"):
        return pg_type.replace(base, "INTEGER", 1)
    if base in ("DOUBLE", "NUMERIC(10,3)", "NUMERIC(5,2)"):
        return "REAL" + pg_type[len(base):] if base != "DOUBLE" else "REAL"
    return pg_type.replace(base, "TEXT", 1)


def create_sql(table, columns, dialect, extra=""):
    cols = ",\n  ".join(f"{name} {sqlite_type(t) if dialect == 'sqlite' else t}" for name, t in columns)
    return f"CREATE TABLE {table} (\n  {cols}{extra}\n);\n"


def to_sqlite(value):
    if isinstance(value, bool):
        return int(value)
    return value


def write_csv(path, columns, rows):
    names = [name for name, _ in columns]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(names)
        for row in rows:
            out = []
            for name in names:
                value = row.get(name)
                out.append("true" if value is True else "false" if value is False else
                           "" if value is None else value)
            writer.writerow(out)


def main():
    parser = argparse.ArgumentParser(description="Build the GreenBuck research database.")
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("exchanges_csv", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()

    out = args.out_dir
    (out / "csv").mkdir(parents=True, exist_ok=True)
    db_path = out / "greenbuck_research.sqlite"
    if db_path.exists():
        db_path.unlink()

    runs = list(run_rows(read_jsonl(args.data_dir / "markers.jsonl")))
    iterations = list(iteration_rows(read_jsonl(args.data_dir / "iterations.jsonl")))
    batch_log = list(batch_log_rows(args.data_dir / "batch_log.txt"))
    header, exchanges = exchange_rows(args.exchanges_csv)
    ex_columns = exchange_columns(header)

    tables = [
        ("runs", RUN_COLUMNS, runs, ""),
        ("iterations", ITERATION_COLUMNS, iterations, ",\n  PRIMARY KEY (run_id, i)"),
        ("batch_log", BATCH_LOG_COLUMNS, batch_log, ""),
        ("exchanges", ex_columns, exchanges, ""),
        ("timing_log", TIMING_LOG_COLUMNS, [], ""),
    ]
    indexes = [
        "CREATE INDEX exchanges_run ON exchanges (run_id);",
        "CREATE INDEX exchanges_condition ON exchanges (encryption, mitigation, label);",
        "CREATE INDEX timing_log_run ON timing_log (run_id);",
    ]

    con = sqlite3.connect(db_path)
    for table, columns, rows, extra in tables:
        con.execute(create_sql(table, columns, "sqlite", extra))
        names = [name for name, _ in columns]
        con.executemany(f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
                        ([to_sqlite(row.get(name)) for name in names] for row in rows))
        write_csv(out / "csv" / f"{table}.csv", columns, rows)
    for statement in indexes:
        con.execute(statement)
    con.commit()
    con.close()

    with open(out / "postgres_load.sql", "w", encoding="utf-8") as f:
        f.write("BEGIN;\n\n")
        for table, columns, _, extra in tables:
            f.write(create_sql(table, columns, "postgres", extra) + "\n")
        for table, _, _, _ in tables:
            f.write(f"\\copy {table} FROM 'csv/{table}.csv' WITH (FORMAT csv, HEADER true)\n")
        f.write("\n" + "\n".join(indexes) + "\n\nCOMMIT;\n")

    print(f"runs {len(runs)}, iterations {len(iterations)}, batch_log {len(batch_log)}, "
          f"exchanges {len(exchanges)} -> {db_path}")


if __name__ == "__main__":
    main()
