"""
GreenBuck Capture Orchestrator
Runs on the Windows dev machine. Coordinates a single research capture:
  1. Starts tcpdump on the Pi via SSH
  2. Triggers the Flutter integration test for the requested action
  3. Stops tcpdump
  4. Pulls the resulting pcap file back to Windows
  5. Writes a markers entry linking request_id to capture window
"""

import argparse
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
PI_CAPTURE_DIR = "/tmp/greenbuck_captures"
LOCAL_CAPTURE_DIR = Path(__file__).parent / "data"
MARKERS_LOG = LOCAL_CAPTURE_DIR / "markers.jsonl"


def ssh_connect():
    """Open an SSH connection to the Pi."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PI_HOST, username=PI_USER, password=PI_PASS)
    return client


def start_tcpdump(ssh, filename):
    """Start tcpdump on the Pi. Returns the real tcpdump pid."""
    remote_path = f"{PI_CAPTURE_DIR}/{filename}"
    ssh.exec_command(f"mkdir -p {PI_CAPTURE_DIR}")
    # Start tcpdump unbuffered in the background. We fetch the real
    # tcpdump pid separately with pgrep (not sudo's or the subshell's).
    cmd = (
        f"sudo tcpdump -i {PI_INTERFACE} -U -w {remote_path} "
        f"port 8000 > /dev/null 2>&1 &"
    )
    ssh.exec_command(cmd)
    time.sleep(2)  # let tcpdump actually start
    _, stdout, _ = ssh.exec_command("pgrep -x tcpdump")
    pid = stdout.read().decode().strip().split("\n")[0]
    return pid, remote_path


def stop_tcpdump(ssh, pid):
    """Stop tcpdump cleanly so it flushes the capture file."""
    ssh.exec_command("sudo pkill -TERM -x tcpdump")
    time.sleep(2)  # give it time to flush and close the file


def trigger_flutter_test(action, encryption, mitigation, platform):
    """Run the Flutter integration test for the requested action."""
    project_root = Path(__file__).parent.parent
    cmd = (
        f'flutter test integration_test/actions_test.dart '
        f'--dart-define=ACTION={action} '
        f'--dart-define=ENCRYPTION={encryption} '
        f'--dart-define=MITIGATION={mitigation} '
        f'--dart-define=PLATFORM={platform}'
    )
    result = subprocess.run(
        cmd, cwd=project_root, capture_output=True, text=True,
        shell=True, encoding='utf-8', errors='replace'
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


def write_marker(request_id, action, platform, encryption, mitigation,
                 run_number, start_time, end_time, pcap_filename):
    """Append a marker entry linking request_id to the pcap file."""
    LOCAL_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "request_id": request_id,
        "action": action,
        "platform": platform,
        "encryption": encryption,
        "mitigation": mitigation,
        "run_number": run_number,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "pcap_filename": pcap_filename,
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
                        choices=["padding", "jitter", "constant", "none"])
    parser.add_argument("--run", type=int, required=True,
                        help="Run number within this configuration")
    args = parser.parse_args()

    request_id = str(uuid.uuid4())
    pcap_filename = (
        f"{args.action}_{args.platform}_{args.encryption}_"
        f"{args.mitigation}_{args.run:03d}.pcap"
    )

    print(f"[*] Run {args.run}: {pcap_filename}")
    print(f"[*] Request ID: {request_id}")

    ssh = ssh_connect()
    try:
        start_time = datetime.now(timezone.utc)
        pid, remote_path = start_tcpdump(ssh, pcap_filename)
        print(f"[*] tcpdump started (pid {pid})")

        success, stdout, stderr = trigger_flutter_test(
            args.action, args.encryption, args.mitigation, args.platform
        )
        if not success:
            print(f"[!] Flutter test failed: {stderr}")

        # Brief buffer so the final response packets land in the capture.
        time.sleep(0.5)

        stop_tcpdump(ssh, pid)
        end_time = datetime.now(timezone.utc)
        print("[*] tcpdump stopped")

        local_path = pull_pcap(ssh, remote_path, pcap_filename)
        print(f"[*] pcap saved: {local_path}")

        write_marker(
            request_id, args.action, args.platform,
            args.encryption, args.mitigation, args.run,
            start_time, end_time, pcap_filename,
        )
        print("[*] marker written")
    finally:
        ssh.close()


if __name__ == "__main__":
    main()