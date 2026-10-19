"""
GreenBuck Capture Orchestrator
Runs on the Windows dev machine. Coordinates a single research capture:
  1. Starts tcpdump on the Pi via SSH
  2. Triggers the Flutter integration test for the requested action
  3. Stops tcpdump (always, even if step 2 fails)
  4. Pulls the resulting pcap file back to Windows
  5. Writes a markers entry linking the run to its capture window
"""

import argparse
import shutil
import subprocess
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
    cmd = (
        f"sudo tcpdump -i {PI_INTERFACE} -U -w {remote_path} "
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
                 run_number, start_time, end_time, pcap_filename, test_passed):
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

    print(f"[*] Run {args.run}: {pcap_filename}")
    print(f"[*] Run ID: {run_id}")
    print(f"[*] Backend: {BASE_URL}")

    ssh = ssh_connect()
    try:
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
        print(f"[*] pcap saved: {local_path}")

        write_marker(
            run_id, args.action, args.platform,
            args.encryption, args.mitigation, args.run,
            start_time, end_time, pcap_filename, success,
        )
        print("[*] marker written")
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
