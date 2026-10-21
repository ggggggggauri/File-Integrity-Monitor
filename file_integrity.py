"""
file_integrity.py
==================
Advanced File Integrity Monitoring System
------------------------------------------
Features:
  - Multiple hash algorithms: MD5, SHA-1, SHA-256 (default), SHA-512
  - Baseline versioning: unlimited historical snapshots
  - Detailed reports: JSON + human-readable text
  - Scheduled auto-monitoring (background thread)
  - Email alerts on tampering detection
  - Whitelist / ignore patterns (glob-based)
  - File metadata tracking (size, mtime)
  - Colored terminal output (no external deps)
  - Rotating log files
  - Full CLI via argparse

Usage examples:
  python file_integrity.py init   --path ./project --algo sha256
  python file_integrity.py check  --path ./project --report --email
  python file_integrity.py watch  --path ./project --interval 60
  python file_integrity.py report --list
  python file_integrity.py report --show <snapshot_id>
"""

import os
import sys
import json
import time
import signal
import smtplib
import hashlib
import fnmatch
import argparse
import threading
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional


# ─────────────────────────────────────────────
# PATHS & DEFAULTS
# ─────────────────────────────────────────────
BASE_DIR        = Path(__file__).parent
BASELINES_DIR   = BASE_DIR / "baselines"
REPORTS_DIR     = BASE_DIR / "reports"
LOGS_DIR        = BASE_DIR / "logs"
CONFIG_FILE     = BASE_DIR / "config.json"
LOG_FILE        = LOGS_DIR / "fim.log"

DEFAULT_ALGO     = "sha256"
DEFAULT_INTERVAL = 60          # seconds for --watch mode
DEFAULT_IGNORES  = ["*.log", "*.tmp", "*.pyc", "__pycache__", ".git"]

SUPPORTED_ALGOS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# ─────────────────────────────────────────────
# COLORS (ANSI — no external libraries needed)
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

def _c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{C.RESET}"

def ok(msg):    print(_c(C.GREEN,  f"  ✔  {msg}"))
def warn(msg):  print(_c(C.YELLOW, f"  ⚠  {msg}"))
def err(msg):   print(_c(C.RED,    f"  ✖  {msg}"))
def info(msg):  print(_c(C.CYAN,   f"  ℹ  {msg}"))
def head(msg):  print(_c(C.BOLD + C.WHITE, f"\n{'═'*52}\n  {msg}\n{'═'*52}"))


# ─────────────────────────────────────────────
# LOGGING SETUP (rotating file log)
# ─────────────────────────────────────────────
def setup_logger() -> logging.Logger:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("FIM")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # Rotating: 5 MB max, keep 3 backups
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)

    return logger

logger = setup_logger()


# ─────────────────────────────────────────────
# CONFIG (email credentials, ignores, etc.)
# ─────────────────────────────────────────────
def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {
        "email": {
            "enabled": False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "sender": "your@gmail.com",
            "password": "app_password_here",
            "recipient": "admin@example.com",
        },
        "ignore_patterns": DEFAULT_IGNORES,
        "default_algo": DEFAULT_ALGO,
    }

def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    ok(f"Config saved → {CONFIG_FILE}")


# ─────────────────────────────────────────────
# HASH CALCULATION
# ─────────────────────────────────────────────
def calculate_hash(file_path: Path, algo: str = "sha256") -> Optional[str]:
    """Return hex digest of a file using the chosen algorithm."""
    hash_fn = SUPPORTED_ALGOS.get(algo)
    if not hash_fn:
        raise ValueError(f"Unsupported algorithm: {algo}. Choose from {list(SUPPORTED_ALGOS)}")

    h = hash_fn()
    try:
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError) as e:
        logger.warning(f"Cannot read {file_path}: {e}")
        return None


# ─────────────────────────────────────────────
# FILE METADATA
# ─────────────────────────────────────────────
def get_metadata(file_path: Path) -> dict:
    """Return size and last-modified time of a file."""
    try:
        stat = file_path.stat()
        return {
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
    except OSError:
        return {"size_bytes": None, "modified_at": None}


# ─────────────────────────────────────────────
# IGNORE PATTERN MATCHING
# ─────────────────────────────────────────────
def should_ignore(file_path: Path, patterns: list[str]) -> bool:
    """Return True if the file path matches any ignore pattern."""
    name = file_path.name
    full = str(file_path)
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
        if fnmatch.fnmatch(full, f"*{pattern}*"):
            return True
    return False


# ─────────────────────────────────────────────
# FOLDER SCAN
# ─────────────────────────────────────────────
def scan_folder(folder_path: Path, algo: str, ignore_patterns: list[str]) -> dict:
    """
    Walk the folder and return a dict:
        { "relative/path/file.txt": { "hash": "...", "size_bytes": N, "modified_at": "..." } }
    """
    results = {}

    for root, dirs, files in os.walk(folder_path):
        # Prune ignored directories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if not should_ignore(Path(root) / d, ignore_patterns)]

        for filename in files:
            full_path = Path(root) / filename

            if should_ignore(full_path, ignore_patterns):
                continue

            rel_path = str(full_path.relative_to(folder_path))
            file_hash = calculate_hash(full_path, algo)
            if file_hash is None:
                continue

            results[rel_path] = {
                "hash": file_hash,
                **get_metadata(full_path),
            }

    return results


# ─────────────────────────────────────────────
# BASELINE MANAGEMENT
# ─────────────────────────────────────────────
def snapshot_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def baseline_path(sid: str) -> Path:
    return BASELINES_DIR / f"baseline_{sid}.json"

def save_baseline(data: dict, sid: str, folder: str, algo: str) -> Path:
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "snapshot_id": sid,
        "created_at": datetime.now().isoformat(),
        "monitored_folder": str(folder),
        "algorithm": algo,
        "file_count": len(data),
        "files": data,
    }
    path = baseline_path(sid)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path

def list_baselines() -> list[dict]:
    if not BASELINES_DIR.exists():
        return []
    baselines = []
    for f in sorted(BASELINES_DIR.glob("baseline_*.json")):
        with open(f) as fh:
            meta = json.load(fh)
        baselines.append({
            "id":      meta.get("snapshot_id"),
            "created": meta.get("created_at"),
            "folder":  meta.get("monitored_folder"),
            "algo":    meta.get("algorithm"),
            "files":   meta.get("file_count"),
        })
    return baselines

def load_latest_baseline() -> Optional[dict]:
    bls = list_baselines()
    if not bls:
        return None
    latest_id = bls[-1]["id"]
    with open(baseline_path(latest_id)) as f:
        return json.load(f)

def load_baseline_by_id(sid: str) -> Optional[dict]:
    path = baseline_path(sid)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────
# DIFF ENGINE
# ─────────────────────────────────────────────
def diff_snapshots(old: dict, new: dict) -> dict:
    """
    Compare two file-hash dicts and return categorized changes.
    Each dict maps relative_path → { hash, size_bytes, modified_at }.
    """
    modified, deleted, new_files, permission_denied = [], [], [], []

    for path, old_info in old.items():
        if path not in new:
            deleted.append({"path": path, **old_info})
        elif new[path]["hash"] != old_info["hash"]:
            modified.append({
                "path":         path,
                "old_hash":     old_info["hash"],
                "new_hash":     new[path]["hash"],
                "old_size":     old_info.get("size_bytes"),
                "new_size":     new[path].get("size_bytes"),
                "modified_at":  new[path].get("modified_at"),
            })

    for path in new:
        if path not in old:
            new_files.append({"path": path, **new[path]})

    return {
        "modified":          modified,
        "deleted":           deleted,
        "new_files":         new_files,
        "permission_denied": permission_denied,
    }


# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────
def save_report(diff: dict, folder: str, algo: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rid = snapshot_id()
    total_changes = (
        len(diff["modified"]) +
        len(diff["deleted"]) +
        len(diff["new_files"])
    )
    payload = {
        "report_id":      rid,
        "generated_at":   datetime.now().isoformat(),
        "monitored_folder": str(folder),
        "algorithm":      algo,
        "summary": {
            "total_changes":    total_changes,
            "modified_count":   len(diff["modified"]),
            "deleted_count":    len(diff["deleted"]),
            "new_files_count":  len(diff["new_files"]),
        },
        "details": diff,
    }
    path = REPORTS_DIR / f"report_{rid}.json"
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path

def print_diff(diff: dict) -> bool:
    """Pretty-print the diff. Returns True if any changes found."""
    modified  = diff["modified"]
    deleted   = diff["deleted"]
    new_files = diff["new_files"]

    any_change = bool(modified or deleted or new_files)

    if not any_change:
        ok("All files intact — no changes detected.")
        return False

    if modified:
        print(_c(C.YELLOW, f"\n  ⚠  MODIFIED ({len(modified)} file(s)):"))
        for f in modified:
            print(f"     {_c(C.YELLOW, f['path'])}")
            print(f"       old hash : {_c(C.DIM, f['old_hash'])}")
            print(f"       new hash : {_c(C.RED,  f['new_hash'])}")
            if f["old_size"] != f["new_size"]:
                print(f"       size     : {f['old_size']} → {f['new_size']} bytes")

    if deleted:
        print(_c(C.RED, f"\n  ✖  DELETED ({len(deleted)} file(s)):"))
        for f in deleted:
            print(f"     {_c(C.RED, f['path'])}")

    if new_files:
        print(_c(C.CYAN, f"\n  +  NEW FILES ({len(new_files)} file(s)):"))
        for f in new_files:
            print(f"     {_c(C.CYAN, f['path'])}  ({f.get('size_bytes', '?')} bytes)")

    return True


# ─────────────────────────────────────────────
# EMAIL ALERTS
# ─────────────────────────────────────────────
def send_email_alert(diff: dict, cfg: dict, folder: str) -> None:
    email_cfg = cfg.get("email", {})
    if not email_cfg.get("enabled"):
        return

    modified  = diff["modified"]
    deleted   = diff["deleted"]
    new_files = diff["new_files"]

    subject = f"[FIM ALERT] Integrity violation detected in {folder}"

    lines = [
        "File Integrity Monitor — Alert",
        f"Folder: {folder}",
        f"Time  : {datetime.now().isoformat()}",
        "",
        f"Modified files  : {len(modified)}",
        f"Deleted files   : {len(deleted)}",
        f"New files found : {len(new_files)}",
    ]

    if modified:
        lines += ["", "── MODIFIED ──"]
        for f in modified:
            lines.append(f"  {f['path']}")
            lines.append(f"    {f['old_hash']} → {f['new_hash']}")

    if deleted:
        lines += ["", "── DELETED ──"]
        for f in deleted:
            lines.append(f"  {f['path']}")

    if new_files:
        lines += ["", "── NEW ──"]
        for f in new_files:
            lines.append(f"  {f['path']}")

    body = "\n".join(lines)

    try:
        msg = MIMEMultipart()
        msg["From"]    = email_cfg["sender"]
        msg["To"]      = email_cfg["recipient"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            server.starttls()
            server.login(email_cfg["sender"], email_cfg["password"])
            server.sendmail(email_cfg["sender"], email_cfg["recipient"], msg.as_string())

        ok(f"Alert email sent → {email_cfg['recipient']}")
        logger.info(f"Alert email sent to {email_cfg['recipient']}")
    except Exception as e:
        warn(f"Email failed: {e}")
        logger.error(f"Email send failed: {e}")


# ─────────────────────────────────────────────
# COMMAND: init
# ─────────────────────────────────────────────
def cmd_init(args) -> None:
    head("INITIALIZE MONITORING")
    cfg = load_config()

    folder = Path(args.path).resolve()
    if not folder.exists():
        err(f"Folder not found: {folder}")
        sys.exit(1)

    algo    = args.algo or cfg.get("default_algo", DEFAULT_ALGO)
    ignores = cfg.get("ignore_patterns", DEFAULT_IGNORES)

    info(f"Scanning   : {folder}")
    info(f"Algorithm  : {algo.upper()}")
    info(f"Ignored    : {', '.join(ignores)}")
    print()

    start = time.time()
    files = scan_folder(folder, algo, ignores)
    elapsed = time.time() - start

    sid  = snapshot_id()
    path = save_baseline(files, sid, str(folder), algo)

    ok(f"Baseline saved  → {path}")
    ok(f"Files hashed    : {len(files)}")
    ok(f"Snapshot ID     : {sid}")
    ok(f"Elapsed         : {elapsed:.2f}s")

    logger.info(f"Baseline initialized | folder={folder} algo={algo} files={len(files)} id={sid}")


# ─────────────────────────────────────────────
# COMMAND: check
# ─────────────────────────────────────────────
def cmd_check(args) -> None:
    head("INTEGRITY CHECK")
    cfg = load_config()

    folder = Path(args.path).resolve()
    if not folder.exists():
        err(f"Folder not found: {folder}")
        sys.exit(1)

    baseline = load_latest_baseline()
    if not baseline:
        err("No baseline found. Run 'init' first.")
        sys.exit(1)

    algo    = baseline.get("algorithm", DEFAULT_ALGO)
    ignores = cfg.get("ignore_patterns", DEFAULT_IGNORES)

    info(f"Folder     : {folder}")
    info(f"Baseline   : {baseline['snapshot_id']}  ({baseline['created_at'][:19]})")
    info(f"Algorithm  : {algo.upper()}")
    print()

    current = scan_folder(folder, algo, ignores)
    diff    = diff_snapshots(baseline["files"], current)

    print_diff(diff)

    any_change = bool(diff["modified"] or diff["deleted"] or diff["new_files"])

    if args.report:
        report_path = save_report(diff, str(folder), algo)
        info(f"Report saved → {report_path}")

    if any_change:
        if args.email or cfg.get("email", {}).get("enabled"):
            send_email_alert(diff, cfg, str(folder))
        logger.warning(
            f"Integrity violations | modified={len(diff['modified'])} "
            f"deleted={len(diff['deleted'])} new={len(diff['new_files'])}"
        )
    else:
        logger.info("Integrity check passed — no changes.")


# ─────────────────────────────────────────────
# COMMAND: watch (scheduled background monitoring)
# ─────────────────────────────────────────────
_stop_event = threading.Event()

def _watch_loop(folder: str, interval: int, args) -> None:
    while not _stop_event.is_set():
        print(_c(C.DIM, f"\n[{datetime.now():%H:%M:%S}] Running scheduled check…"))
        cmd_check(args)
        _stop_event.wait(timeout=interval)

def cmd_watch(args) -> None:
    head("WATCH MODE  (press Ctrl+C to stop)")
    interval = args.interval or DEFAULT_INTERVAL
    info(f"Interval : every {interval}s")
    info(f"Folder   : {args.path}")

    def _sigint(sig, frame):
        print(_c(C.YELLOW, "\n\n  Stopping watch mode…"))
        _stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    t = threading.Thread(target=_watch_loop, args=(args.path, interval, args), daemon=True)
    t.start()
    t.join()


# ─────────────────────────────────────────────
# COMMAND: report
# ─────────────────────────────────────────────
def cmd_report(args) -> None:
    if args.list:
        head("AVAILABLE BASELINES")
        bls = list_baselines()
        if not bls:
            warn("No baselines found. Run 'init' first.")
            return
        for b in bls:
            print(f"  {_c(C.CYAN, b['id'])}  │  {b['created'][:19]}  │  {b['algo'].upper()}  │  {b['files']} files  │  {b['folder']}")

        head("AVAILABLE REPORTS")
        if not REPORTS_DIR.exists():
            warn("No reports yet. Run 'check --report' to generate one.")
            return
        reports = sorted(REPORTS_DIR.glob("report_*.json"))
        if not reports:
            warn("No reports found.")
            return
        for r in reports:
            with open(r) as f:
                meta = json.load(f)
            s = meta.get("summary", {})
            print(
                f"  {_c(C.CYAN, meta['report_id'])}  │  {meta['generated_at'][:19]}  │  "
                f"mod={s.get('modified_count',0)}  del={s.get('deleted_count',0)}  new={s.get('new_files_count',0)}"
            )
        return

    if args.show:
        path = REPORTS_DIR / f"report_{args.show}.json"
        if not path.exists():
            err(f"Report {args.show} not found.")
            return
        with open(path) as f:
            data = json.load(f)
        print(json.dumps(data, indent=2))
        return

    warn("Use --list or --show <id>")


# ─────────────────────────────────────────────
# COMMAND: config
# ─────────────────────────────────────────────
def cmd_config(args) -> None:
    head("CONFIGURE")
    cfg = load_config()

    if args.setup_email:
        print(_c(C.CYAN, "  Enter email alert settings (leave blank to keep existing):"))
        fields = [
            ("smtp_host",  "SMTP host",      cfg["email"].get("smtp_host")),
            ("smtp_port",  "SMTP port",      cfg["email"].get("smtp_port")),
            ("sender",     "Sender email",   cfg["email"].get("sender")),
            ("password",   "App password",   cfg["email"].get("password")),
            ("recipient",  "Recipient email",cfg["email"].get("recipient")),
        ]
        for key, label, default in fields:
            val = input(f"  {label} [{default}]: ").strip()
            if val:
                cfg["email"][key] = int(val) if key == "smtp_port" and val.isdigit() else val
        cfg["email"]["enabled"] = input("  Enable email alerts? [y/N]: ").strip().lower() == "y"

    if args.add_ignore:
        cfg.setdefault("ignore_patterns", DEFAULT_IGNORES)
        cfg["ignore_patterns"].append(args.add_ignore)
        ok(f"Added ignore pattern: {args.add_ignore}")

    if args.list_ignores:
        print("  Current ignore patterns:")
        for p in cfg.get("ignore_patterns", []):
            print(f"    - {p}")

    save_config(cfg)


# ─────────────────────────────────────────────
# COMMAND: compare (diff two baselines)
# ─────────────────────────────────────────────
def cmd_compare(args) -> None:
    head(f"COMPARE BASELINES  {args.old}  →  {args.new}")
    b_old = load_baseline_by_id(args.old)
    b_new = load_baseline_by_id(args.new)

    if not b_old:
        err(f"Baseline '{args.old}' not found.")
        return
    if not b_new:
        err(f"Baseline '{args.new}' not found.")
        return

    info(f"Old : {b_old['created_at'][:19]}  ({b_old['algorithm'].upper()}, {b_old['file_count']} files)")
    info(f"New : {b_new['created_at'][:19]}  ({b_new['algorithm'].upper()}, {b_new['file_count']} files)")

    if b_old["algorithm"] != b_new["algorithm"]:
        warn("Algorithms differ — hashes are not directly comparable.")

    diff = diff_snapshots(b_old["files"], b_new["files"])
    print_diff(diff)


# ─────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file_integrity",
        description="Advanced File Integrity Monitoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  init     Create a baseline snapshot of a folder
  check    Compare current state against the latest baseline
  watch    Run check repeatedly on a schedule
  report   List or view saved reports and baselines
  compare  Diff two specific baseline snapshots
  config   Configure email alerts and ignore patterns
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # ── init ──
    p_init = sub.add_parser("init", help="Initialize baseline")
    p_init.add_argument("--path", required=True, help="Folder to monitor")
    p_init.add_argument("--algo", choices=list(SUPPORTED_ALGOS), default=None,
                        help=f"Hash algorithm (default: {DEFAULT_ALGO})")

    # ── check ──
    p_check = sub.add_parser("check", help="Verify integrity")
    p_check.add_argument("--path", required=True, help="Folder to check")
    p_check.add_argument("--report", action="store_true", help="Save JSON report")
    p_check.add_argument("--email",  action="store_true", help="Send email alert on changes")
    p_check.add_argument("--interval", type=int, default=None)  # used internally by watch

    # ── watch ──
    p_watch = sub.add_parser("watch", help="Monitor on a schedule")
    p_watch.add_argument("--path", required=True, help="Folder to monitor")
    p_watch.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                         help=f"Seconds between checks (default: {DEFAULT_INTERVAL})")
    p_watch.add_argument("--report", action="store_true")
    p_watch.add_argument("--email",  action="store_true")

    # ── report ──
    p_rep = sub.add_parser("report", help="List or view reports")
    p_rep.add_argument("--list", action="store_true", help="List all baselines & reports")
    p_rep.add_argument("--show", metavar="ID",        help="Print a specific report as JSON")

    # ── compare ──
    p_cmp = sub.add_parser("compare", help="Diff two baseline snapshots")
    p_cmp.add_argument("--old", required=True, metavar="SNAPSHOT_ID")
    p_cmp.add_argument("--new", required=True, metavar="SNAPSHOT_ID")

    # ── config ──
    p_cfg = sub.add_parser("config", help="Configure settings")
    p_cfg.add_argument("--setup-email",  action="store_true", help="Configure SMTP alert settings")
    p_cfg.add_argument("--add-ignore",   metavar="PATTERN",   help="Add a file ignore pattern")
    p_cfg.add_argument("--list-ignores", action="store_true", help="List current ignore patterns")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "init":    cmd_init,
        "check":   cmd_check,
        "watch":   cmd_watch,
        "report":  cmd_report,
        "compare": cmd_compare,
        "config":  cmd_config,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
