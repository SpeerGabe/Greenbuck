"""
GreenBuck Capture Orchestrator
Runs on the Windows dev machine. Coordinates a single research capture:
  0. Resets the server database to a fixed seed (reset_state.sql)
  1. Starts tcpdump on the Pi via SSH
  2. Triggers the Flutter integration test for the requested action
  3. Stops tcpdump (always, even if step 2 fails)
  4. Pulls the resulting pcap file back to Windows
  5. Writes a markers entry linking the run to its capture window,
     with packet_count and seed_sha
"""

import argparse
import hashlib  # fingerprint of the seed file, written to markers
import shutil
import struct   # reads pcap record headers to count packets
import subprocess
import sys
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
# Backend runs on the Pi, so default to it. Override in .env if needed.
BASE_URL = os.environ.get("BASE_URL", f"https://{PI_HOST}:8000")
PI_CAPTURE_DIR = "/tmp/greenbuck_captures"
LOCAL_CAPTURE_DIR = Path(__file__).parent / "data"
MARKERS_LOG = LOCAL_CAPTURE_DIR / "markers.jsonl"

# Per-run DB reset: reset_state.sql is read locally and piped over SSH into
# this command on the server. Default: the postgres superuser over the local
# socket; -n makes sudo fail instead of prompting for a password.
# Override with DB_RESET_CMD in .env.
RESET_SQL_PATH = Path(__file__).parent / "reset_state.sql"
DB_RESET_CMD = os.environ.get(
    "DB_RESET_CMD",
    "sudo -n -u postgres psql -d greenbuck -v ON_ERROR_STOP=1 -q -f -",
)

# Captures must go over TLS: refuse an http:// backend.
if not BASE_URL.startswith("https://"):
    sys.exit(f"[!] BASE_URL must be https:// for captures (got {BASE_URL})")


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
    """Open an SSH connection to the Pi."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PI_HOST, username=PI_USER, password=PI_PASS)
    return client


def ssh_run(ssh, cmd):
    """Run a command on the Pi and wait for it to finish. Returns (exit_code, stdout)."""
    _, stdout, _ = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()  # blocks until the command exits
    return exit_code, stdout.read().decode().strip()


def start_tcpdump(ssh, filename):
    """Start tcpdump on the Pi. Returns the real tcpdump pid."""
    remote_path = f"{PI_CAPTURE_DIR}/{filename}"
    ssh_run(ssh, f"mkdir -p {PI_CAPTURE_DIR}")  # wait for it, so tcpdump never races it
    # Start tcpdump unbuffered in the background. We fetch the real
    # tcpdump pid separately with pgrep (not sudo's or the subshell's).
    # --immediate-mode delivers each packet as it arrives, so nothing is left
    # buffered when tcpdump is stopped.
    cmd = (
        f"sudo tcpdump -i {PI_INTERFACE} --immediate-mode -U -w {remote_path} "
        f"port 8000 > /dev/null 2>&1 &"
    )
    ssh.exec_command(cmd)
    time.sleep(2)  # let tcpdump actually start
    _, out = ssh_run(ssh, "pgrep -x tcpdump")
    pid = out.split("\n")[0]
    if not pid:
        raise RuntimeError("tcpdump did not start on the Pi (check sudo / interface name)")
    return pid, remote_path


def stop_tcpdump(ssh, pid):
    """Stop tcpdump cleanly so it flushes the capture file."""
    ssh_run(ssh, "sudo pkill -TERM -x tcpdump")
    time.sleep(2)  # give it time to flush and close the file


def trigger_flutter_test(action, encryption, mitigation, platform, run_id):
    """Run the Flutter integration test for the requested action."""
    project_root = Path(__file__).parent.parent
    flutter = shutil.which("flutter")  # resolves flutter.bat on Windows
    if flutter is None:
        raise RuntimeError("flutter not found on PATH")
    # One list element per argument: no shell string, so no missing-space bugs.
    cmd = [
        flutter, "test", "integration_test/actions_test.dart",
        f"--dart-define=ACTION={action}",
        f"--dart-define=ENCRYPTION={encryption}",
        f"--dart-define=MITIGATION={mitigation}",
        f"--dart-define=PLATFORM={platform}",
        f"--dart-define=BASE_URL={BASE_URL}",
        f"--dart-define=RUN_ID={run_id}",
    ]
    result = subprocess.run(
        cmd, cwd=project_root, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    return result.returncode == 0, result.stdout, result.stderr


def pull_pcap(ssh, remote_path, local_filename):
    """SCP the pcap file from Pi to local data directory."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    local_path = LOCAL_CAPTURE_DIR / local_filename
    sftp = ssh.open_sftp()
    sftp.get(remote_path, str(local_path))
    sftp.close()
    return local_path


def write_marker(run_id, action, platform, encryption, mitigation,
                 run_number, start_time, end_time, pcap_filename, test_passed,
                 packet_count, seed_sha):
    """Append a marker entry linking the run to the pcap file."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "run_id": run_id,
        "action": action,
        "platform": platform,
        "encryption": encryption,
        "mitigation": mitigation,
        "run_number": run_number,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "pcap_filename": pcap_filename,
        "test_passed": test_passed,
        "packet_count": packet_count,  # 0 = nothing captured
        "seed_sha": seed_sha,          # which reset_state.sql the run started from
    }
    with open(MARKERS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True,
                        choices=["view_history", "make_transfer",
                                 "check_balance", "login", "logout", "register"])
    parser.add_argument("--platform", required=True, choices=["android", "ios"])
    parser.add_argument("--encryption", required=True,
                        choices=["aesgcm", "chacha20", "aescbc", "none"])
    parser.add_argument("--mitigation", required=True,
                        choices=["padding", "jitter", "constant", "batching", "none"])
    parser.add_argument("--run", type=int, required=True,
                        help="Run number within this configuration")
    args = parser.parse_args()

    run_id = str(uuid.uuid4())
    pcap_filename = (
        f"{args.action}_{args.platform}_{args.encryption}_"
        f"{args.mitigation}_{args.run:03d}.pcap"
    )

    # Don't overwrite an existing capture.
    if (LOCAL_CAPTURE_DIR / pcap_filename).exists():
        sys.exit(f"[!] {pcap_filename} already exists in {LOCAL_CAPTURE_DIR}; use a new --run number")

    print(f"[*] Run {args.run}: {pcap_filename}")
    print(f"[*] Run ID: {run_id}")
    print(f"[*] Backend: {BASE_URL}")

    ssh = ssh_connect()
    try:
        # Reset before tcpdump starts so every run begins from the same database state.
        seed_sha = reset_server_state(ssh)
        print(f"[*] DB reset to seed {seed_sha}")

        start_time = datetime.now(timezone.utc)
        pid, remote_path = start_tcpdump(ssh, pcap_filename)
        print(f"[*] tcpdump started (pid {pid})")

        success = False
        try:
            success, stdout, stderr = trigger_flutter_test(
                args.action, args.encryption, args.mitigation, args.platform, run_id
            )
            if not success:
                print(f"[!] Flutter test failed:\n{stdout[-2000:]}\n{stderr[-2000:]}")

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

        write_marker(
            run_id, args.action, args.platform,
            args.encryption, args.mitigation, args.run,
            start_time, end_time, pcap_filename, success,
            packet_count, seed_sha,
        )
        print("[*] marker written")
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
