"""
Splits GreenBuck capture pcaps into labeled request/response exchanges.

Each TCP connection to the server is reassembled per direction and parsed into
TLS records. After the TLS 1.3 handshake (client: everything through its
Finished record; server: its encrypted handshake records and session tickets),
consecutive client records form one request and the server records that follow
form its response. Labels come from the run's schedule in markers.jsonl: every
scheduled action sends a fixed sequence of requests, so the run's exchanges are
matched to that sequence in order. A run whose exchange count or per-connection
grouping differs from the schedule is reported and left unlabeled.

Usage:
  python3 extract_exchanges.py capture/data out_dir
"""

import argparse
import csv
import itertools
import json
import sys
from pathlib import Path

import dpkt

SERVER_PORT = 8000
TLS_HANDSHAKE, TLS_CCS, TLS_APPDATA = 22, 20, 23
SERVER_ENCRYPTED_HANDSHAKE_RECORDS = 4
SERVER_SESSION_TICKETS = 2
RESPONSE_RECORDS = 2  # uvicorn sends response headers and body as separate TLS records

# Request labels each scheduled action produces, and how they group into TCP
# connections (a pause longer than the client's idle timeout opens a new one).
ACTION_REQUESTS = {
    "default": {
        "L": [["login", "check_balance", "view_history"]],
        "H": [["login", "check_balance", "view_history"], ["view_history"]],
        "T": [["login", "check_balance", "view_history"], ["view_history"], ["make_transfer", "view_history"]],
        "B": [["login", "check_balance", "view_history"], ["check_balance", "view_history"]],
        "R": [["register"]],
        "O": [["login", "check_balance", "view_history"], ["logout"]],
    },
    "batching": {
        "L": [["login"], ["batch:check_balance+view_history"]],
        "H": [["login"], ["batch:check_balance+view_history"], ["batch:view_history"]],
        "T": [["login"], ["batch:check_balance+view_history"], ["batch:view_history"],
              ["batch:make_transfer", "batch:view_history"]],
        "B": [["login"], ["batch:check_balance+view_history"], ["batch:check_balance+view_history"]],
        "R": [["register"]],
        "O": [["login"], ["batch:check_balance+view_history"], ["logout"]],
    },
}
ACTION_NAMES = {"L": "login", "O": "logout", "R": "register", "H": "view_history",
                "T": "make_transfer", "B": "check_balance"}


def expected_layout(marker):
    """Returns [(action, [labels per connection])] for the run's schedule."""
    table = ACTION_REQUESTS["batching" if marker["mitigation"] == "batching" else "default"]
    return [(ACTION_NAMES[code], table[code]) for code in marker["schedule"]]


def tcp_packets(path):
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        linktype = reader.datalink()
        for ts, buf in reader:
            if linktype == dpkt.pcap.DLT_EN10MB:
                ip = dpkt.ethernet.Ethernet(buf).data
            elif linktype == dpkt.pcap.DLT_LINUX_SLL:
                ip = dpkt.sll.SLL(buf).data
            elif linktype == 276:
                ip = dpkt.sll2.SLL2(buf).data
            elif linktype in (dpkt.pcap.DLT_RAW, 101):
                ip = dpkt.ip.IP(buf)
            else:
                raise ValueError(f"unsupported link type {linktype}")
            if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) and isinstance(ip.data, dpkt.tcp.TCP):
                yield ts, ip, ip.data


def reassemble(segments):
    """Orders (ts, seq, data, wire_len) segments into one stream.

    Returns (stream bytes, [(stream offset, ts)] per packet, gap flag).
    """
    segments.sort(key=lambda s: (s[1], s[0]))
    stream = bytearray()
    marks = []
    gap = False
    start = segments[0][1] if segments else 0
    for ts, seq, data, _ in segments:
        offset = seq - start
        end = len(stream)
        if offset > end:
            gap = True
            continue
        new = data[end - offset:]
        if not new:
            continue
        marks.append((len(stream), len(stream) + len(new), ts))
        stream.extend(new)
    return bytes(stream), marks, gap


def tls_records(stream, marks):
    """Returns [(content type, record length incl. 5-byte header, ts first byte, ts last byte)]."""
    def ts_at(pos):
        for lo, hi, ts in marks:
            if lo <= pos < hi:
                return ts
        return marks[-1][2]

    records = []
    pos = 0
    while pos + 5 <= len(stream):
        ctype = stream[pos]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        end = pos + 5 + length
        if end > len(stream):
            break
        records.append((ctype, 5 + length, ts_at(pos), ts_at(end - 1)))
        pos = end
    return records


def connections(path):
    conns = {}
    for ts, ip, tcp in tcp_packets(path):
        if tcp.dport == SERVER_PORT:
            key, side = tcp.sport, "client"
        elif tcp.sport == SERVER_PORT:
            key, side = tcp.dport, "server"
        else:
            continue
        conn = conns.setdefault(key, {"first_ts": ts, "client": [], "server": [],
                                      "client_pkts": [], "server_pkts": []})
        conn[f"{side}_pkts"].append((ts, len(ip)))
        if tcp.data:
            conn[side].append((ts, tcp.seq, bytes(tcp.data), len(ip)))
    return sorted(conns.items(), key=lambda kv: kv[1]["first_ts"])


def exchanges_in(conn):
    """Splits one connection's application data into request/response exchanges."""
    problems = []
    c_stream, c_marks, c_gap = reassemble(conn["client"])
    s_stream, s_marks, s_gap = reassemble(conn["server"])
    if c_gap or s_gap:
        problems.append("missing TCP data")
    if not c_marks or not s_marks:
        return [], problems + ["no data in one direction"]
    c_recs = tls_records(c_stream, c_marks)
    s_recs = tls_records(s_stream, s_marks)

    c_app = [r for r in c_recs if r[0] == TLS_APPDATA][1:]
    s_app = [r for r in s_recs if r[0] == TLS_APPDATA][SERVER_ENCRYPTED_HANDSHAKE_RECORDS + SERVER_SESSION_TICKETS:]

    if len(s_app) % RESPONSE_RECORDS:
        return [], problems + [f"{len(s_app)} server records is not a whole number of responses"]
    responses = [s_app[i:i + RESPONSE_RECORDS] for i in range(0, len(s_app), RESPONSE_RECORDS)]
    requests = [[] for _ in responses]
    for rec in c_app:
        k = sum(1 for resp in responses if resp[-1][3] < rec[2])
        if k >= len(responses):
            problems.append("client data after the last response")
            continue
        requests[k].append(rec)
    if any(not req for req in requests):
        return [], problems + ["a response with no request"]

    out = []
    for req, resp in zip(requests, responses):
        out.append({
            "req_records": len(req),
            "req_bytes": sum(r[1] for r in req),
            "req_start": req[0][2],
            "req_end": req[-1][3],
            "resp_records": len(resp),
            "resp_bytes": sum(r[1] for r in resp),
            "resp_start": resp[0][2],
            "resp_end": resp[-1][3],
        })
    for ex in out:
        lo, hi = ex["req_start"], ex["resp_end"]
        ex["req_packets"] = sum(1 for ts, _ in conn["client_pkts"] if lo <= ts <= hi)
        ex["resp_packets"] = sum(1 for ts, _ in conn["server_pkts"] if lo <= ts <= hi)
        ex["req_wire_bytes"] = sum(n for ts, n in conn["client_pkts"] if lo <= ts <= hi)
        ex["resp_wire_bytes"] = sum(n for ts, n in conn["server_pkts"] if lo <= ts <= hi)
    return out, problems


def process_run(marker, data_dir):
    conns = connections(data_dir / marker["pcap_filename"])
    run_problems = []
    per_conn = []
    for port, conn in conns:
        exchanges, problems = exchanges_in(conn)
        run_problems += [f"port {port}: {p}" for p in problems]
        if exchanges:
            per_conn.append((port, conn, exchanges))

    expected_groups = [(iteration, action, labels)
                       for iteration, (action, conns_) in enumerate(expected_layout(marker))
                       for labels in conns_]
    observed_sizes = [len(ex) for _, _, ex in per_conn]
    expected_sizes = [len(labels) for _, _, labels in expected_groups]
    observed_cuts = set(itertools.accumulate(observed_sizes))
    expected_cuts = set(itertools.accumulate(expected_sizes))
    if sum(observed_sizes) != sum(expected_sizes) or not observed_cuts <= expected_cuts:
        run_problems.append(f"connection grouping {observed_sizes} != expected {expected_sizes}")
        return [], run_problems
    if observed_sizes != expected_sizes:
        run_problems.append(f"note: connection reused across steps {observed_sizes} vs {expected_sizes}")

    expected_seq = [(iteration, action, label)
                    for iteration, action, labels in expected_groups for label in labels]
    rows = []
    run_start = conns[0][1]["first_ts"]
    k = 0
    for conn_index, (port, conn, exchanges) in enumerate(per_conn):
        for pos, ex in enumerate(exchanges):
            iteration, action, label = expected_seq[k]
            k += 1
            rows.append({
                "run_id": marker["run_id"],
                "pcap_filename": marker["pcap_filename"],
                "encryption": marker["encryption"],
                "mitigation": marker["mitigation"],
                "run_number": marker["run_number"],
                "iteration": iteration,
                "action": action,
                "label": label,
                "conn_index": conn_index,
                "client_port": port,
                "pos_in_conn": pos,
                "req_records": ex["req_records"],
                "req_bytes": ex["req_bytes"],
                "resp_records": ex["resp_records"],
                "resp_bytes": ex["resp_bytes"],
                "req_packets": ex["req_packets"],
                "resp_packets": ex["resp_packets"],
                "req_wire_bytes": ex["req_wire_bytes"],
                "resp_wire_bytes": ex["resp_wire_bytes"],
                "t_req_start_s": round(ex["req_start"] - run_start, 6),
                "ttfb_ms": round((ex["resp_start"] - ex["req_start"]) * 1000, 3),
                "latency_ms": round((ex["resp_start"] - ex["req_end"]) * 1000, 3),
                "resp_transfer_ms": round((ex["resp_end"] - ex["resp_start"]) * 1000, 3),
                "exchange_ms": round((ex["resp_end"] - ex["req_start"]) * 1000, 3),
                "gap_before_ms": round((ex["req_start"] - (exchanges[pos - 1]["resp_end"] if pos
                                                            else conn["first_ts"])) * 1000, 3),
            })
    return rows, run_problems


def main():
    parser = argparse.ArgumentParser(description="Extract labeled exchanges from GreenBuck pcaps.")
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.data_dir / "markers.jsonl", encoding="utf-8") as f:
        markers = [json.loads(line) for line in f if line.strip()]

    all_rows, failures = [], {}
    for n, marker in enumerate(markers, 1):
        rows, problems = process_run(marker, args.data_dir)
        if rows:
            all_rows += rows
        if problems:
            failures[marker["pcap_filename"]] = problems
        if n % 100 == 0:
            print(f"  {n}/{len(markers)} runs", file=sys.stderr)

    with open(args.out_dir / "exchanges.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0]))
        writer.writeheader()
        writer.writerows(all_rows)
    with open(args.out_dir / "extract_problems.json", "w", encoding="utf-8") as f:
        json.dump(failures, f, indent=2)

    labeled_runs = len({r["run_id"] for r in all_rows})
    print(f"{labeled_runs}/{len(markers)} runs labeled, {len(all_rows)} exchanges, "
          f"{len(failures)} runs with problems or notes")
    for name, problems in list(failures.items())[:15]:
        print(f"  {name}: {'; '.join(problems)}")


if __name__ == "__main__":
    main()
