#!/usr/bin/env python3
"""eShield remote development helper.

Modes:
  sync   - one-shot incremental sync Windows -> Linux (default)
  watch  - continuous incremental sync (recommended for development)
  build  - sync + compile eBPF + user-space binary
  test   - sync + compile + run integration tests
  exec   - sync + run an arbitrary remote command/script

Recommended workflow (scheme 1):
  1. On Windows: python .sync_remote.py watch
  2. Edit code locally; it auto-syncs to /tmp/eshield-sync on the test box.
  3. On Linux: run cargo build / tests directly, no need to git push first.
  4. Git commit/push stays on Windows.
"""

import argparse
import os
import stat
import sys
import time

import paramiko

HOST = "118.193.35.84"
USER = "ubuntu"
REMOTE_DIR = "/tmp/eshield-sync"
LOCAL_DIR = os.path.dirname(os.path.abspath(__file__))


def load_password() -> str:
    """Load remote password from env, .remote_pass file, or prompt."""
    pwd = os.environ.get("ESHIELD_REMOTE_PASS")
    if pwd:
        return pwd
    pass_file = os.path.join(LOCAL_DIR, ".remote_pass")
    if os.path.exists(pass_file):
        with open(pass_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    import getpass

    return getpass.getpass("Remote password: ")


PASSWORD = load_password()

EXCLUDES = {".git", "target", ".claude", ".remote_pass"}


def should_upload(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    for part in parts:
        if not part:
            continue
        if part in EXCLUDES or part.startswith("."):
            return False
    return True


def scan_local(root: str):
    """Return {rel_path: (mtime, size)} for all local files."""
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        rel_dir_unix = rel_dir.replace("\\", "/")
        if not should_upload(rel_dir_unix):
            dirnames[:] = []
            continue

        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d not in EXCLUDES
        ]

        for f in filenames:
            if f.startswith("."):
                continue
            rel = rel_dir_unix + "/" + f if rel_dir_unix else f
            if not should_upload(rel):
                continue
            full = os.path.join(dirpath, f)
            try:
                st = os.stat(full)
            except OSError:
                continue
            result[rel] = (st.st_mtime, st.st_size)
    return result


def scan_remote(sftp, root: str):
    """Return {rel_path: (mtime, size)} for all remote files."""
    result = {}

    def walk(remote_path: str, rel_prefix: str):
        try:
            attrs = sftp.listdir_attr(remote_path)
        except IOError:
            return
        for attr in attrs:
            name = attr.filename
            if name.startswith("."):
                continue
            rel = (rel_prefix + "/" + name) if rel_prefix else name
            if not should_upload(rel):
                continue
            full_remote = remote_path + "/" + name
            if stat.S_ISDIR(attr.st_mode):
                walk(full_remote, rel)
            else:
                result[rel] = (attr.st_mtime, attr.st_size)

    walk(root, "")
    return result


def ensure_remote_dir(sftp, remote_path: str):
    try:
        sftp.mkdir(remote_path)
    except IOError:
        pass


def upload_file(sftp, local_root: str, rel: str, remote_root: str):
    local_file = os.path.join(local_root, rel.replace("/", os.sep))
    remote_file = remote_root + "/" + rel
    remote_parent = remote_root + "/" + os.path.dirname(rel.replace("/", os.sep))
    if remote_parent != remote_root:
        ensure_remote_dir(sftp, remote_parent.replace("\\", "/"))
    sftp.put(local_file, remote_file)


def remove_remote(sftp, remote_root: str, rel: str):
    try:
        sftp.remove(remote_root + "/" + rel)
    except IOError:
        pass


def sync_incremental(sftp, ssh, local: str, remote: str):
    """Upload changed/new files and remove remote files no longer present locally."""
    local_files = scan_local(local)
    remote_files = scan_remote(sftp, remote)

    uploaded = 0
    removed = 0

    for rel, (lmtime, lsize) in local_files.items():
        if rel not in remote_files:
            print(f"  + {rel}")
            upload_file(sftp, local, rel, remote)
            uploaded += 1
        else:
            rmtime, rsize = remote_files[rel]
            # Upload if newer or size differs. Add small tolerance for mtime
            # rounding over SFTP.
            if lmtime > rmtime + 1 or lsize != rsize:
                print(f"  ~ {rel}")
                upload_file(sftp, local, rel, remote)
                uploaded += 1

    for rel in remote_files:
        if rel not in local_files:
            print(f"  - {rel}")
            remove_remote(sftp, remote, rel)
            removed += 1

    if uploaded == 0 and removed == 0:
        print("  (already up to date)")
    else:
        print(f"  {uploaded} uploaded, {removed} removed")


def sync_full(sftp, ssh, local: str, remote: str):
    """Nuke remote dir and re-upload everything."""
    print("Performing full sync...")
    ssh.exec_command(f"rm -rf {remote} && mkdir -p {remote}")
    time.sleep(0.5)
    ensure_remote_dir(sftp, remote)
    for rel in sorted(scan_local(local).keys()):
        upload_file(sftp, local, rel, remote)
    print("Full sync complete.")


def run_command(ssh, cmd: str) -> int:
    print(f"\n>>> {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out:
        print(out, end="")
    if err:
        print(err, file=sys.stderr, end="")
    return stdout.channel.recv_exit_status()


def env_setup() -> str:
    return (
        "export PATH=/home/ubuntu/.cargo/bin:$PATH "
        "&& export RUSTUP_HOME=/home/ubuntu/.rustup "
        "&& export CARGO_HOME=/home/ubuntu/.cargo"
    )


def run_build(ssh, remote_dir: str) -> int:
    env = env_setup()
    cmds = [
        f"cd {remote_dir} && {env} && cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q",
        f"cd {remote_dir} && {env} && cargo build --package eshield --target x86_64-unknown-linux-musl --release -q",
    ]
    for cmd in cmds:
        code = run_command(ssh, cmd)
        if code != 0:
            return code
    return 0


def run_test(ssh, remote_dir: str) -> int:
    code = run_build(ssh, remote_dir)
    if code != 0:
        return code
    cmd = f"cd {remote_dir} && sudo SKIP_BUILD=1 bash ./tests/netns_test.sh"
    return run_command(ssh, cmd)


def run_exec(ssh, remote_dir: str, cmd: str) -> int:
    full = f"cd {remote_dir} && {cmd}"
    return run_command(ssh, full)


def watch(sftp, ssh, local: str, remote: str):
    print(f"Watching {local} -> {remote} (Ctrl+C to stop)")
    last_snapshot = {}
    while True:
        snapshot = scan_local(local)
        if snapshot != last_snapshot:
            print(f"\n[{time.strftime('%H:%M:%S')}] Changes detected, syncing...")
            sync_incremental(sftp, ssh, local, remote)
            last_snapshot = snapshot
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(
        description="eShield remote sync / build / test helper"
    )
    parser.add_argument(
        "mode",
        choices=["sync", "watch", "build", "test", "exec"],
        default="sync",
        nargs="?",
        help="sync=incremental sync; watch=continuous sync; build=sync+compile; test=sync+compile+test; exec=sync+run remote command",
    )
    parser.add_argument(
        "--cmd",
        default="",
        help="Command to run in exec mode (relative to remote_dir)",
    )
    args = parser.parse_args()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD)
    sftp = ssh.open_sftp()

    exit_code = 0
    try:
        if args.mode == "sync":
            print(f"Incremental sync to {HOST}:{REMOTE_DIR}")
            sync_incremental(sftp, ssh, LOCAL_DIR, REMOTE_DIR)
        elif args.mode == "watch":
            watch(sftp, ssh, LOCAL_DIR, REMOTE_DIR)
        elif args.mode == "build":
            print(f"Incremental sync to {HOST}:{REMOTE_DIR}")
            sync_incremental(sftp, ssh, LOCAL_DIR, REMOTE_DIR)
            exit_code = run_build(ssh, REMOTE_DIR)
        elif args.mode == "test":
            print(f"Incremental sync to {HOST}:{REMOTE_DIR}")
            sync_incremental(sftp, ssh, LOCAL_DIR, REMOTE_DIR)
            exit_code = run_test(ssh, REMOTE_DIR)
        elif args.mode == "exec":
            if not args.cmd:
                print("ERROR: --cmd required for exec mode", file=sys.stderr)
                sys.exit(2)
            print(f"Incremental sync to {HOST}:{REMOTE_DIR}")
            sync_incremental(sftp, ssh, LOCAL_DIR, REMOTE_DIR)
            exit_code = run_exec(ssh, REMOTE_DIR, args.cmd)
    finally:
        sftp.close()
        ssh.close()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
