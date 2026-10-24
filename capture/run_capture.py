"""
GreenBuck Capture Orchestrator
Runs on the dev machine. Coordinates one research capture run:
  0. Resets the server database to a fixed seed (reset_state.sql)
  1. Starts tcpdump on the capture host via SSH
  2. Runs the looped Flutter integration test over a shuffled schedule of actions
  3. Stops tcpdump (always, even if step 2 fails)
  4. Pulls the resulting pcap file back to the dev machine
  5. Writes a markers entry for the run (schedule, seed, packet_count, seed_sha)
     and one iterations entry per action the test reported
"""

import argparse
import collections
import hashlib  # fingerprint of the seed file, written to markers
import random
import secrets
import shutil
import struct   # reads pcap record headers to count packets
import subprocess
import sys
import threading
import time
import uuid
import json
import os
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timezone
import paramiko

load_dotenv()
# ===== Configuration =====
PI_HOST = os.environ["PI_HOST"]
PI_USER = os.environ["PI_USER"]
PI_PASS = os.environ["PI_PASS"]
PI_INTERFACE = os.environ["PI_INTERFACE"]
# Backend runs on the capture host, so default to it. Override in .env if needed.
BASE_URL = os.environ.get("BASE_URL", f"https://{PI_HOST}:8000")
# Optional flutter device id (from `flutter devices`), for when more than one is attached.
FLUTTER_DEVICE = os.environ.get("FLUTTER_DEVICE")
PI_CAPTURE_DIR = "/tmp/greenbuck_captures"
LOCAL_CAPTURE_DIR = Path(__file__).parent / "data"
MARKERS_LOG = LOCAL_CAPTURE_DIR / "markers.jsonl"
ITERATIONS_LOG = LOCAL_CAPTURE_DIR / "iterations.jsonl"

# Per-run DB reset: reset_state.sql is read locally and piped over SSH into
# this command on the server. Default: the postgres superuser over the local
# socket; -n makes sudo fail instead of prompting for a password.
# Override with DB_RESET_CMD in .env.
RESET_SQL_PATH = Path(__file__).parent / "reset_state.sql"
DB_RESET_CMD = os.environ.get(
    "DB_RESET_CMD",
    "sudo -n -u postgres psql -d greenbuck -v ON_ERROR_STOP=1 -q -f -",
)

# Action names and the one-character codes the integration test reads from SCHEDULE.
ACTION_CODES = {
    "login": "L",
    "logout": "O",
    "register": "R",
    "view_history": "H",
    "make_transfer": "T",
    "check_balance": "B",
}
DEFAULT_PER_ACTION = 10
DEFAULT_THINK_MS = 2000

# Under fixed padding with encryption, view_history stays at its padded size up to
# 35 transactions (6 seeded + 29 added). The DB resets once per run, so transfers
# per run are capped below that.
MAX_TRANSFERS_PER_RUN = 25

# The test prints one line per iteration: "GB_ITER {json}".
ITER_TAG = "GB_ITER "

# Watchdog for the flutter test process: build/install time plus a per-iteration allowance.
BUILD_TIMEOUT_S = 900
ITERATION_TIMEOUT_S = 90

# Captures must go over TLS: refuse an http:// backend.
if not BASE_URL.startswith("https://"):
    sys.exit(f"[!] BASE_URL must be https:// for captures (got {BASE_URL})")


def parse_mix(text):
    """Parse 'action=count,action=count' into {action: count}."""
    counts = {}
    for part in text.split(","):
        name, sep, count = part.strip().partition("=")
        if not sep or name not in ACTION_CODES or not count.isdigit():
            raise argparse.ArgumentTypeError(
                f"bad --mix entry {part!r}; expected action=count with action in {sorted(ACTION_CODES)}"
            )
        counts[name] = int(count)
    return counts


def build_schedule(counts, seed):
    """List each action counts[action] times, shuffled with a seeded RNG."""
    schedule = [action for action in ACTION_CODES for _ in range(counts.get(action, 0))]
    random.Random(seed).shuffle(schedule)
    return schedule


def reset_server_state(ssh):
    """Reset the server database to the fixed seed in reset_state.sql.

    Returns a short sha256 of the seed file (written to markers.jsonl).
    Raises if the reset fails.
    """
    sql = RESET_SQL_PATH.read_text(encoding="utf-8")
    stdin, stdout, stderr = ssh.exec_command(DB_RESET_CMD)
    stdin.write(sql)
    stdin.channel.shutdown_write()  # EOF so psql runs the script and exits
    exit_code = stdout.channel.recv_exit_status()
    if exit_code != 0:
        raise RuntimeError(
            f"DB reset failed (exit {exit_code}): {stderr.read().decode().strip()}"
        )
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()[:12]


def count_pcap_packets(path):
    """Count packet records in a classic libpcap file (tcpdump -w)."""
    with open(path, "rb") as f:
        header = f.read(24)  # global header
        if len(header) < 24:
            return 0
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):    # little-endian (us / ns)
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):  # big-endian (us / ns)
            endian = ">"
        else:
            raise ValueError(f"{path} is not a libpcap file")
        count = 0
        while True:
            record = f.read(16)  # per-packet header: ts_sec, ts_frac, incl_len, orig_len
            if len(record) < 16:
                break
            incl_len = struct.unpack(endian + "IIII", record)[2]
            f.seek(incl_len, 1)  # skip the packet bytes
            count += 1
    return count


def ssh_connect():
    """Open an SSH connection to the capture host."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PI_HOST, username=PI_USER, password=PI_PASS)
    return client


def ssh_run(ssh, cmd):
    """Run a command on the capture host and wait for it to finish. Returns (exit_code, stdout)."""
    _, stdout, _ = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()  # blocks until the command exits
    return exit_code, stdout.read().decode().strip()


def start_tcpdump(ssh, filename):
    """Start tcpdump on the capture host. Returns the real tcpdump pid."""
    remote_path = f"{PI_CAPTURE_DIR}/{filename}"
    log_path = f"{PI_CAPTURE_DIR}/tcpdump.log"
    ssh_run(ssh, f"mkdir -p {PI_CAPTURE_DIR} && chmod 777 {PI_CAPTURE_DIR}")  # wait for it, so tcpdump never races it
    # Start tcpdump unbuffered in the background. We fetch the real
    # tcpdump pid separately with pgrep (not sudo's or the subshell's).
    # --immediate-mode delivers each packet as it arrives, so nothing is left
    # buffered when tcpdump is stopped.
    # -Z root keeps tcpdump running as root when it opens the output file, so it
    # can write into a directory owned by the SSH user.
    # sudo -n fails instead of waiting for a password; sudo's and tcpdump's
    # messages go to tcpdump.log.
    cmd = (
        f"sudo -n tcpdump -i {PI_INTERFACE} --immediate-mode -U -w {remote_path} "
        f"port 8000 > {log_path} 2>&1 &"
    )
    ssh.exec_command(cmd)
    time.sleep(2)  # let tcpdump actually start
    _, out = ssh_run(ssh, "pgrep -x tcpdump")
    pid = out.split("\n")[0]
    if not pid:
        _, log = ssh_run(ssh, f"cat {log_path}")
        raise RuntimeError(f"tcpdump did not start on the capture host. tcpdump.log:\n{log}")
    return pid, remote_path


def stop_tcpdump(ssh, pid):
    """Stop tcpdump cleanly so it flushes the capture file."""
    ssh_run(ssh, "sudo -n pkill -TERM -x tcpdump")
    time.sleep(2)  # give it time to flush and close the file


def trigger_flutter_test(schedule, encryption, mitigation, platform, run_id, think_ms):
    """Run the looped integration test over the schedule.

    Streams the test's output, printing progress for each GB_ITER line.
    Returns (passed, iterations, output_tail): iterations is the list of
    GB_ITER records, output_tail the last lines of flutter's output.
    """
    project_root = Path(__file__).parent.parent
    flutter = shutil.which("flutter")  # resolves flutter.bat on Windows
    if flutter is None:
        raise RuntimeError("flutter not found on PATH")
    codes = "".join(ACTION_CODES[action] for action in schedule)
    # One list element per argument: no shell string, so no missing-space bugs.
    cmd = [flutter, "test", "integration_test/actions_test.dart"]
    if FLUTTER_DEVICE:
        cmd += ["-d", FLUTTER_DEVICE]
    cmd += [
        f"--dart-define=SCHEDULE={codes}",
        f"--dart-define=THINK_MS={think_ms}",
        f"--dart-define=ENCRYPTION={encryption}",
        f"--dart-define=MITIGATION={mitigation}",
        f"--dart-define=PLATFORM={platform}",
        f"--dart-define=BASE_URL={BASE_URL}",
        f"--dart-define=RUN_ID={run_id}",
    ]
    proc = subprocess.Popen(
        cmd, cwd=project_root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    watchdog = threading.Timer(BUILD_TIMEOUT_S + ITERATION_TIMEOUT_S * len(schedule), proc.kill)
    watchdog.start()
    iterations = []
    tail = collections.deque(maxlen=60)
    try:
        for line in proc.stdout:
            line = line.rstrip()
            tail.append(line)
            pos = line.find(ITER_TAG)
            if pos == -1:
                continue
            try:
                record = json.loads(line[pos + len(ITER_TAG):])
            except json.JSONDecodeError:
                continue
            iterations.append(record)
            status = "ok" if record.get("ok") else f"FAILED: {record.get('error')}"
            print(f"    [{len(iterations)}/{len(schedule)}] {record.get('action')} {status}")
        returncode = proc.wait()
    finally:
        watchdog.cancel()
    return returncode == 0, iterations, "\n".join(tail)


def pull_pcap(ssh, remote_path, local_filename):
    """SCP the pcap file from the capture host to the local data directory."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    local_path = LOCAL_CAPTURE_DIR / local_filename
    sftp = ssh.open_sftp()
    sftp.get(remote_path, str(local_path))
    sftp.close()
    return local_path


def write_marker(entry):
    """Append a marker entry linking the run to its pcap file."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    with open(MARKERS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def write_iterations(run_id, iterations):
    """Append one line per reported iteration, tagged with the run id."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    with open(ITERATIONS_LOG, "a") as f:
        for record in iterations:
            f.write(json.dumps({"run_id": run_id, **record}) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=["android", "ios"])
    parser.add_argument("--encryption", required=True,
                        choices=["aesgcm", "chacha20", "aescbc", "none"])
    parser.add_argument("--mitigation", required=True,
                        choices=["padding", "random_padding", "jitter", "constant", "batching", "none"])
    parser.add_argument("--run", type=int, required=True,
                        help="Run number within this configuration")
    parser.add_argument("--per-action", type=int, default=DEFAULT_PER_ACTION,
                        help=f"Iterations of each action (default {DEFAULT_PER_ACTION})")
    parser.add_argument("--mix", type=parse_mix,
                        help="Iterations per action, e.g. make_transfer=20,logout=20,register=20,login=5. "
                             "Unlisted actions get 0. Overrides --per-action.")
    parser.add_argument("--seed", type=int,
                        help="Seed for the schedule shuffle (default: random, written to markers)")
    parser.add_argument("--think-ms", type=int, default=DEFAULT_THINK_MS,
                        help=f"Pause after each step, in ms (default {DEFAULT_THINK_MS})")
    args = parser.parse_args()

    counts = args.mix if args.mix is not None else {a: args.per_action for a in ACTION_CODES}
    if sum(counts.values()) == 0:
        sys.exit("[!] Schedule is empty")
    if counts.get("make_transfer", 0) > MAX_TRANSFERS_PER_RUN:
        sys.exit(f"[!] make_transfer is capped at {MAX_TRANSFERS_PER_RUN} per run "
                 f"(view_history outgrows fixed padding past that)")
    seed = args.seed if args.seed is not None else secrets.randbelow(2**31)
    schedule = build_schedule(counts, seed)

    run_id = str(uuid.uuid4())
    pcap_filename = f"{args.platform}_{args.encryption}_{args.mitigation}_{args.run:03d}.pcap"

    # Don't overwrite an existing capture.
    if (LOCAL_CAPTURE_DIR / pcap_filename).exists():
        sys.exit(f"[!] {pcap_filename} already exists in {LOCAL_CAPTURE_DIR}; use a new --run number")

    print(f"[*] Run {args.run}: {pcap_filename}")
    print(f"[*] Run ID: {run_id}")
    print(f"[*] Backend: {BASE_URL}")
    print(f"[*] Schedule: {len(schedule)} iterations, seed {seed}, "
          + ", ".join(f"{a}={n}" for a, n in counts.items() if n))

    ssh = ssh_connect()
    try:
        # Reset before tcpdump starts so every run begins from the same database state.
        seed_sha = reset_server_state(ssh)
        print(f"[*] DB reset to seed {seed_sha}")

        start_time = datetime.now(timezone.utc)
        pid, remote_path = start_tcpdump(ssh, pcap_filename)
        print(f"[*] tcpdump started (pid {pid})")

        success, iterations, output_tail = False, [], ""
        try:
            print("[*] Building and running the integration test...")
            success, iterations, output_tail = trigger_flutter_test(
                schedule, args.encryption, args.mitigation, args.platform, run_id, args.think_ms
            )
            if not success:
                print(f"[!] Flutter test failed. Last output:\n{output_tail}")

            # Brief buffer so the final response packets land in the capture.
            time.sleep(0.5)
        finally:
            # Runs even if the test step raises, so tcpdump is never orphaned.
            stop_tcpdump(ssh, pid)
            end_time = datetime.now(timezone.utc)
            print("[*] tcpdump stopped")

        local_path = pull_pcap(ssh, remote_path, pcap_filename)
        packet_count = count_pcap_packets(local_path)
        print(f"[*] pcap saved: {local_path} ({packet_count} packets)")
        if packet_count == 0:
            print("[!] WARNING: pcap is empty. Check PI_INTERFACE (WiFi is usually wlan0/wlp*, not eth0).")

        n_ok = sum(1 for record in iterations if record.get("ok"))
        n_failed = len(iterations) - n_ok
        if len(iterations) < len(schedule):
            print(f"[!] Test reported {len(iterations)} of {len(schedule)} iterations")
        print(f"[*] Iterations: {n_ok} ok, {n_failed} failed")

        write_iterations(run_id, iterations)
        write_marker({
            "run_id": run_id,
            "platform": args.platform,
            "encryption": args.encryption,
            "mitigation": args.mitigation,
            "run_number": args.run,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "pcap_filename": pcap_filename,
            "test_passed": success,
            "packet_count": packet_count,  # 0 = nothing captured
            "seed_sha": seed_sha,          # which reset_state.sql the run started from
            "mix": counts,
            "schedule_seed": seed,
            "schedule": "".join(ACTION_CODES[a] for a in schedule),
            "think_ms": args.think_ms,
            "iterations_reported": len(iterations),
            "iterations_ok": n_ok,
            "iterations_failed": n_failed,
        })
        print("[*] marker written")
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
