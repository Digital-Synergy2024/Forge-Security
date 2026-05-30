"""
================================================================================
 FORGE/DB  —  Database Security & Credential Console
 Digital-Synergy LLC
================================================================================

A LOCAL desktop tool for hardening and managing MySQL / MariaDB on your XAMPP
VPS, plus scanning your htdocs apps for their database credentials.

WHAT IT DOES
  • Connection      — connect to MySQL on localhost (password kept in memory only)
  • Security Audit  — flags anonymous users, '%' wildcard hosts, blank passwords,
                      over-privileged app accounts, the leftover 'test' DB, etc.
  • Users           — list/flag every account, create scoped per-app users in a
                      couple of clicks, change passwords, lock hosts, drop users
  • App Credentials — scan C:\\xampp\\htdocs for DB connections (PHP + .env),
                      show which app uses which user/db, and safely rotate the
                      credentials in-place (always backs the file up first)

SECURITY NOTES (read me)
  • Run this ONLY on the VPS itself, over your RDP session.
  • Keep this file OUTSIDE C:\\xampp\\htdocs  — anything in htdocs is served to
    the public by Apache. Put it somewhere like C:\\Tools\\.
  • It never stores your MySQL password to disk. Only the htdocs path / host /
    port / last username are remembered (in forgedb_config.json next to it).
  • Connect as root (or another admin account) to use the management features.

REQUIREMENTS
    pip install customtkinter pymysql

RUN
    python forge_db.py

OPTIONAL — compile to a single .exe
    pip install pyinstaller
    pyinstaller --noconsole --onefile forge_db.py
================================================================================
"""

import os
import re
import sys
import csv
import json
import shutil
import string
import secrets
import datetime
import subprocess
from pathlib import Path
from typing import Any, cast

import tkinter as tk
from tkinter import messagebox, filedialog

import customtkinter as ctk

try:
    import pymysql
    from pymysql.cursors import DictCursor
    PYMYSQL_OK = True
except Exception:
    pymysql = None      # type: ignore[assignment]
    DictCursor = None   # type: ignore[assignment]
    PYMYSQL_OK = False


# ------------------------------------------------------------------------------
# Palette  (Digital-Synergy: cyan / gold on deep navy)
# ------------------------------------------------------------------------------
C = {
    "bg":        "#0a0e1a",
    "panel":     "#111829",
    "card":      "#0f1524",
    "card_hi":   "#16203a",
    "border":    "#1f2c47",
    "cyan":      "#00e5ff",
    "cyan_dim":  "#0b7c8c",
    "gold":      "#ffc24b",
    "text":      "#e6edf6",
    "muted":     "#8696b3",
    "red":       "#ff5d6c",
    "amber":     "#ffb020",
    "green":     "#3ddc84",
    "row_a":     "#0f1524",
    "row_b":     "#121a2c",
}

SEV_COLORS = {"HIGH": C["red"], "MEDIUM": C["amber"], "LOW": C["gold"], "OK": C["green"], "INFO": C["cyan"]}

MONO = "Consolas"

# When frozen by PyInstaller, __file__ lives in a temp dir; user-writable files
# (config, reports, backups) must live next to the .exe instead.
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "forgedb_config.json"
REPORTS_DIR = APP_DIR / "reports"


def resource_path(*parts) -> Path:
    """Resolve a bundled read-only asset both in source and PyInstaller onefile mode."""
    base = Path(getattr(sys, "_MEIPASS", APP_DIR))
    return base.joinpath(*parts)


def ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


# privileges offered when creating a scoped app user (whitelist — nothing else)
CRUD_PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE"]
SCHEMA_PRIVS = ["CREATE", "ALTER", "DROP", "INDEX", "REFERENCES"]
ALLOWED_PRIVS = set(CRUD_PRIVS + SCHEMA_PRIVS)

# global privilege columns in mysql.user used to summarise an account
GLOBAL_PRIV_COLS = [
    "Select_priv", "Insert_priv", "Update_priv", "Delete_priv", "Create_priv",
    "Drop_priv", "Reload_priv", "Shutdown_priv", "Process_priv", "File_priv",
    "References_priv", "Index_priv", "Alter_priv", "Show_db_priv", "Super_priv",
    "Create_tmp_table_priv", "Lock_tables_priv", "Execute_priv", "Repl_slave_priv",
    "Repl_client_priv", "Create_view_priv", "Show_view_priv", "Create_routine_priv",
    "Alter_routine_priv", "Create_user_priv", "Event_priv", "Trigger_priv",
]
BROAD_SET = ["Select_priv", "Insert_priv", "Update_priv", "Delete_priv", "Create_priv", "Drop_priv"]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
SAFE_PW_CHARS = string.ascii_letters + string.digits + "!@#%^*-_=+."


# ==============================================================================
# Helpers (no GUI / no DB)  — unit-testable
# ==============================================================================
def generate_password(length: int = 24) -> str:
    """Strong password using only chars that are safe inside .env and single-quoted PHP."""
    return "".join(secrets.choice(SAFE_PW_CHARS) for _ in range(max(12, length)))


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_config(cfg: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def backup_file(path: Path) -> Path:
    """Copy path -> path.<timestamp>.bak and return the backup path."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = path.parent / (path.name + f".{stamp}.bak")
    shutil.copy2(path, bak)
    return bak


# ---- htdocs scanner ----------------------------------------------------------
# Each finding: dict(file, app, kind, host, user, db, pw_status, raw, editable)
#   pw_status: "blank" | "set" | "variable"
#   editable : True when we can safely rewrite the credentials in place

_RE_MYSQLI_CONNECT = re.compile(
    r"""mysqli_connect\s*\(\s*
        (['"])(?P<host>.*?)\1\s*,\s*
        (['"])(?P<user>.*?)\3\s*,\s*
        (['"])(?P<pw>.*?)\5\s*
        (?:,\s*(['"])(?P<db>.*?)\7\s*)?
        """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_RE_NEW_MYSQLI = re.compile(
    r"""new\s+mysqli\s*\(\s*
        (['"])(?P<host>.*?)\1\s*,\s*
        (['"])(?P<user>.*?)\3\s*,\s*
        (['"])(?P<pw>.*?)\5\s*
        (?:,\s*(['"])(?P<db>.*?)\7\s*)?
        """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_RE_PDO = re.compile(
    r"""new\s+PDO\s*\(\s*
        (['"])mysql:host=(?P<host>[^;'"]+);(?:port=\d+;)?dbname=(?P<db>[^;'"]+)\1\s*,\s*
        (['"])(?P<user>.*?)\4\s*,\s*
        (['"])(?P<pw>.*?)\6
        """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
# loose detector: a connect call exists but uses variables / unparseable args
_RE_LOOSE = re.compile(r"(mysqli_connect\s*\(|new\s+mysqli\s*\(|new\s+PDO\s*\(\s*['\"]mysql:)", re.IGNORECASE)

_ENV_KEYS = {
    "host": ("DB_HOST", "MYSQL_HOST", "DATABASE_HOST"),
    "user": ("DB_USERNAME", "DB_USER", "MYSQL_USER", "DATABASE_USER"),
    "pw":   ("DB_PASSWORD", "DB_PASS", "MYSQL_PASSWORD", "DATABASE_PASSWORD"),
    "db":   ("DB_DATABASE", "DB_NAME", "MYSQL_DATABASE", "DATABASE_NAME"),
}

SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__", ".cache"}


def _app_name(file_path: Path, root: Path) -> str:
    try:
        rel = file_path.relative_to(root)
        return rel.parts[0] if len(rel.parts) > 1 else "(root)"
    except Exception:
        return file_path.parent.name


def _pw_status(pw: str) -> str:
    return "blank" if pw == "" else "set"


def scan_php_text(text: str):
    """Return a list of parsed connections from one PHP file's contents."""
    out = []
    for rx, kind in ((_RE_MYSQLI_CONNECT, "mysqli_connect"),
                     (_RE_NEW_MYSQLI, "new mysqli"),
                     (_RE_PDO, "PDO")):
        for m in rx.finditer(text):
            d = m.groupdict()
            out.append({
                "kind": kind,
                "host": d.get("host", ""),
                "user": d.get("user", ""),
                "db": d.get("db") or "",
                "pw_status": _pw_status(d.get("pw", "")),
                "raw": m.group(0).strip(),
                "editable": True,
            })
    if not out and _RE_LOOSE.search(text):
        out.append({
            "kind": "connect (variables)", "host": "", "user": "", "db": "",
            "pw_status": "variable", "raw": "", "editable": False,
        })
    return out


def parse_env_text(text: str):
    """Return (host, user, pw_status, db, found_keys) from a .env file's contents."""
    vals = {}
    found = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, _, val = s.partition("=")
        key = key.strip().upper()
        val = val.strip().strip('"').strip("'")
        for field, names in _ENV_KEYS.items():
            if key in names and field not in vals:
                vals[field] = val
                found[field] = key
    if not found:
        return None
    pw_present = "pw" in vals and vals["pw"] != ""
    return {
        "kind": ".env",
        "host": vals.get("host", ""),
        "user": vals.get("user", ""),
        "db": vals.get("db", ""),
        "pw_status": "set" if pw_present else ("blank" if "pw" in found else "variable"),
        "raw": "", "editable": True, "env_keys": found,
    }


def scan_htdocs(root_str: str, progress=None):
    """Walk htdocs and return a list of credential findings."""
    root = Path(root_str)
    findings = []
    if not root.exists():
        return findings
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            fpath = Path(dirpath) / fn
            low = fn.lower()
            try:
                if low.endswith(".php"):
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                    for conn in scan_php_text(text):
                        conn.update({"file": str(fpath), "app": _app_name(fpath, root)})
                        findings.append(conn)
                elif low == ".env" or low.startswith(".env"):
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                    env = parse_env_text(text)
                    if env:
                        env.update({"file": str(fpath), "app": _app_name(fpath, root)})
                        findings.append(env)
            except Exception:
                continue
        if progress:
            progress(len(findings))
    return findings


def rewrite_env_credentials(path: Path, env_keys: dict, new_user: str, new_pw: str):
    """Rewrite DB user/password lines in a .env file. Returns (preview_before, preview_after)."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines(keepends=False)
    user_key = env_keys.get("user")
    pw_key = env_keys.get("pw")
    before, after = [], []

    def repl(line):
        s = line.strip()
        if "=" in s and not s.startswith("#"):
            k = s.split("=", 1)[0].strip().upper()
            if user_key and k == user_key:
                return f"{line.split('=')[0]}={new_user}"
            if pw_key and k == pw_key:
                return f"{line.split('=')[0]}={new_pw}"
        return line

    new_lines = []
    for ln in lines:
        nl = repl(ln)
        if nl != ln:
            before.append(ln)
            after.append(nl)
        new_lines.append(nl)

    if not before:
        return None, None
    backup_file(path)
    path.write_text("\n".join(new_lines) + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
    return "\n".join(before), "\n".join(after)


def rewrite_php_credentials(path: Path, old_raw: str, kind: str, new_user: str, new_pw: str):
    """Rewrite the user/password string-literals inside a single connect call. Returns (before, after)."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if old_raw not in text:
        return None, None

    if kind == "PDO":
        rx, ui, pi = _RE_PDO, "user", "pw"
    elif kind == "new mysqli":
        rx, ui, pi = _RE_NEW_MYSQLI, "user", "pw"
    else:
        rx, ui, pi = _RE_MYSQLI_CONNECT, "user", "pw"

    m = rx.search(old_raw)
    if not m:
        return None, None
    new_block = old_raw
    # replace user then password literals by their captured spans (work right-to-left)
    spans = sorted([(m.start(ui), m.end(ui), new_user), (m.start(pi), m.end(pi), new_pw)],
                   key=lambda t: t[0], reverse=True)
    for start, end, val in spans:
        new_block = new_block[:start] + val + new_block[end:]

    new_text = text.replace(old_raw, new_block, 1)
    backup_file(path)
    path.write_text(new_text, encoding="utf-8")
    return old_raw, new_block


# ---- audit report export -----------------------------------------------------
def build_report(server_info: str, findings, users, scan_results=None) -> dict:
    """Assemble a structured, serialisable audit report."""
    sev_counts = {}
    norm_findings = []
    for f in findings:
        sev, title, detail = f[0], f[1], f[2]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        norm_findings.append({"severity": sev, "title": title, "detail": detail})
    return {
        "tool": "FORGE/DB — Digital-Synergy LLC",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "server": server_info,
        "summary": sev_counts,
        "findings": norm_findings,
        "users": users or [],
        "app_credentials": scan_results or [],
    }


def export_report_json(report: dict, path: Path) -> Path:
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def export_report_csv(report: dict, path: Path) -> Path:
    """Flat CSV of findings — the part most useful for compliance spreadsheets."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["generated_at", report.get("generated_at", "")])
        w.writerow(["server", report.get("server", "")])
        w.writerow([])
        w.writerow(["severity", "title", "detail"])
        for f in report.get("findings", []):
            w.writerow([f.get("severity", ""), f.get("title", ""), f.get("detail", "")])
    return path


def timestamped_report_paths(prefix: str = "forgedb-audit"):
    """Return (json_path, csv_path) in the reports dir with a shared timestamp."""
    ensure_reports_dir()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return (REPORTS_DIR / f"{prefix}-{stamp}.json",
            REPORTS_DIR / f"{prefix}-{stamp}.csv")


# severity weights for the security score (read-only, non-destructive metric)
SCORE_WEIGHTS = {"HIGH": 28, "MEDIUM": 12, "LOW": 4}


def compute_security_score(findings) -> dict:
    """Turn audit findings into a 0–100 posture score + letter grade.

    Purely informational: it never changes anything, it just summarises how many
    HIGH/MEDIUM/LOW issues remain so users can watch the number climb as they fix
    things (or as they preview fixes in simulation mode).
    """
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for sev, *_ in findings:
        if sev in counts:
            counts[sev] += 1
    penalty = sum(SCORE_WEIGHTS[s] * n for s, n in counts.items())
    score = max(0, 100 - penalty)
    if score >= 90:
        grade, color = "A", "#3ddc84"
    elif score >= 75:
        grade, color = "B", "#9ad06b"
    elif score >= 60:
        grade, color = "C", "#ffc24b"
    elif score >= 40:
        grade, color = "D", "#ffb020"
    else:
        grade, color = "F", "#ff5d6c"
    return {"score": score, "grade": grade, "color": color, "counts": counts}



# ==============================================================================
# Network helpers  (Windows: listener audit + firewall control + UAC elevation)
# ==============================================================================
try:
    import ctypes
except Exception:
    ctypes = None

IS_WINDOWS = (os.name == "nt")
FW_PREFIX = "FORGE-DB:"
LOCKOUT_PORTS = {"3389"}                       # never silently block — risks self-lockout
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def is_admin() -> bool:
    if not IS_WINDOWS or ctypes is None:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relaunch elevated via UAC. Returns True if a relaunch was triggered."""
    if not IS_WINDOWS or ctypes is None:
        return False
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            exe = sys.executable
            params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return True
    except Exception:
        return False


def _run(cmd):
    """Run a command list -> (returncode, combined output)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                           creationflags=CREATE_NO_WINDOW)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, str(e)


def parse_tasklist_csv(text: str) -> dict:
    """`tasklist /FO CSV /NH` -> {pid: image_name}."""
    out = {}
    for line in text.splitlines():
        parts = line.split('","')
        if len(parts) >= 2:
            name = parts[0].strip().strip('"')
            pid = parts[1].strip().strip('"')
            if pid.isdigit():
                out[pid] = name
    return out


def _scope_label(addr: str) -> str:
    a = addr.strip("[]")
    if a in ("0.0.0.0", "::", "*"):
        return "ALL"
    if a in ("127.0.0.1", "::1"):
        return "local"
    return a


def parse_netstat(text: str, proc_map: dict):
    """`netstat -ano` -> list of listener dicts."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        local = parts[1]
        if proto == "TCP":
            if len(parts) < 5 or parts[3].upper() != "LISTENING":
                continue
            pid = parts[4]
        else:
            pid = parts[-1]
        if local.startswith("["):
            host, _, port = local.rpartition("]:")
            host = host + "]"
        else:
            host, _, port = local.rpartition(":")
        scope = _scope_label(host)
        out.append({"proto": proto, "host": host, "port": port, "scope": scope,
                    "pid": pid, "process": proc_map.get(pid, "?"), "exposed": scope == "ALL"})
    seen, uniq = set(), []
    for r in out:
        key = (r["proto"], r["host"], r["port"], r["pid"])
        if key not in seen:
            seen.add(key); uniq.append(r)
    uniq.sort(key=lambda r: (not r["exposed"], r["port"].zfill(6)))
    return uniq


def list_listeners():
    if not IS_WINDOWS:
        return []
    _, tl = _run(["tasklist", "/FO", "CSV", "/NH"])
    proc_map = parse_tasklist_csv(tl)
    _, ns = _run(["netstat", "-ano"])
    return parse_netstat(ns, proc_map)


def fw_rule_name(action, proto, port):
    return f"{FW_PREFIX} {action} {proto} {port} in"


def fw_add_rule(action, proto, port):
    """action in {block, allow} -> (ok, message, command_string)."""
    name = fw_rule_name(action, proto, port)
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={name}", "dir=in", f"action={action}",
           f"protocol={proto}", f"localport={port}"]
    rc, out = _run(cmd)
    return rc == 0, out.strip(), subprocess.list2cmdline(cmd)


def fw_delete_rule(name):
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
    rc, out = _run(cmd)
    return rc == 0, out.strip(), subprocess.list2cmdline(cmd)


def fw_add_rule_cmd(action, proto, port) -> str:
    """Return the exact netsh command string for an add-rule (no execution)."""
    name = fw_rule_name(action, proto, port)
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={name}", "dir=in", f"action={action}",
           f"protocol={proto}", f"localport={port}"]
    return subprocess.list2cmdline(cmd)


def fw_delete_rule_cmd(name) -> str:
    """Return the exact netsh command string for a delete-rule (no execution)."""
    return subprocess.list2cmdline(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])


def parse_netsh_rules(text: str):
    """`netsh advfirewall firewall show rule name=all` -> list of FORGE-DB rule dicts."""
    rules, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        if not s or ":" not in s:
            continue
        key, _, val = s.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "rule name":
            if cur and cur.get("name", "").startswith(FW_PREFIX):
                rules.append(cur)
            cur = {"name": val}
        elif cur is not None:
            if key == "direction":
                cur["dir"] = val
            elif key == "action":
                cur["action"] = val
            elif key == "protocol":
                cur["proto"] = val
            elif key in ("localport", "local port"):
                cur["port"] = val
            elif key == "enabled":
                cur["enabled"] = val
    if cur and cur.get("name", "").startswith(FW_PREFIX):
        rules.append(cur)
    return rules


def fw_list_forge_rules():
    if not IS_WINDOWS:
        return []
    _, out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    return parse_netsh_rules(out)


# ==============================================================================
# Database layer
# ==============================================================================
class DB:
    def __init__(self):
        self.conn = None
        self.info = ""
        # --- simulation / dry-run -------------------------------------------
        # When simulate is True, every mutating statement is RECORDED instead of
        # executed. Read-only queries (q) always run so previews stay accurate.
        self.simulate = False
        self.sim_log = []        # list of recorded SQL statements (newest last)

    @property
    def connected(self) -> bool:
        return self.conn is not None

    def clear_sim_log(self):
        self.sim_log = []

    def _require(self):
        """Return the live connection or raise a clear error (keeps type-checkers happy)."""
        if self.conn is None:
            raise RuntimeError("Not connected to a database.")
        return self.conn

    def connect(self, host, port, user, password):
        if not PYMYSQL_OK or pymysql is None:
            raise RuntimeError("PyMySQL is not installed. Run: pip install pymysql")
        self.close()
        self.conn = pymysql.connect(
            host=host, port=int(port), user=user, password=password,
            cursorclass=cast(Any, DictCursor), connect_timeout=6, autocommit=True,
        )
        with self.conn.cursor() as cur:
            cur.execute("SELECT VERSION() AS v")
            row = cur.fetchone()
            self.info = (row or {}).get("v", "") if isinstance(row, dict) else ""
        return self.info

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    def q(self, sql, args=None) -> list:
        conn = self._require()
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cast(list, list(cur.fetchall() or []))

    def x(self, sql):
        # Single mutation chokepoint: honour simulation here so EVERY write path
        # (create user, drop, lock, password change, hardening) is dry-runnable.
        if self.simulate:
            self.sim_log.append(sql.strip())
            return
        conn = self._require()
        with conn.cursor() as cur:
            cur.execute(sql)

    # ---- data --------------------------------------------------------------
    def databases(self):
        rows = self.q("SHOW DATABASES")
        skip = {"information_schema", "performance_schema", "mysql", "sys", "phpmyadmin", "test"}
        return [list(r.values())[0] for r in rows]

    def all_databases(self):
        return [list(r.values())[0] for r in self.q("SHOW DATABASES")]

    def users(self):
        rows = self.q("SELECT * FROM mysql.user")
        out = []
        for r in rows:
            pw = (r.get("Password") or "").strip()
            auth = (r.get("authentication_string") or "").strip()
            has_pw = bool(pw) or bool(auth)
            plugin = (r.get("plugin") or "").strip()
            ys = [c for c in GLOBAL_PRIV_COLS if str(r.get(c, "N")).upper() == "Y"]
            grant = str(r.get("Grant_priv", "N")).upper() == "Y"
            broad = all(str(r.get(c, "N")).upper() == "Y" for c in BROAD_SET)
            if broad and len(ys) >= len(BROAD_SET):
                priv = "ALL PRIVILEGES" if len(ys) >= 20 else "broad"
            elif ys:
                priv = "partial (" + ",".join(p.replace("_priv", "") for p in ys[:4]) + ("…" if len(ys) > 4 else "") + ")"
            else:
                priv = "no global"
            out.append({
                "user": r.get("User", ""), "host": r.get("Host", ""),
                "has_pw": has_pw, "plugin": plugin,
                "priv": priv, "grant": grant, "broad": broad, "anon": r.get("User", "") == "",
            })
        return out

    def grants(self, user, host):
        try:
            rows = self.q("SHOW GRANTS FOR %s@%s", (user, host))
            return [list(r.values())[0] for r in rows]
        except Exception as e:
            return [f"(could not read grants: {e})"]

    # ---- mutations ---------------------------------------------------------
    def create_scoped_user(self, user, hosts, db, privs):
        if not USERNAME_RE.match(user):
            raise ValueError("Username must be letters, numbers or underscore (max 32).")
        if db not in self.all_databases():
            raise ValueError("Unknown database.")
        bad = [p for p in privs if p not in ALLOWED_PRIVS]
        if bad:
            raise ValueError(f"Disallowed privilege(s): {', '.join(bad)}")
        if not privs:
            raise ValueError("Pick at least one privilege.")
        pw = generate_password()
        priv_sql = ", ".join(privs)
        db_q = "`" + db.replace("`", "``") + "`"
        conn = self._require()
        for h in hosts:
            pw_lit = conn.escape(pw)            # safely quoted literal
            self.x(f"CREATE USER '{user}'@'{h}' IDENTIFIED BY {pw_lit}")
            self.x(f"GRANT {priv_sql} ON {db_q}.* TO '{user}'@'{h}'")
        self.x("FLUSH PRIVILEGES")
        return pw

    def set_password(self, user, host, new_pw):
        lit = self._require().escape(new_pw)
        try:
            self.x(f"ALTER USER '{user}'@'{host}' IDENTIFIED BY {lit}")
        except Exception:
            self.x(f"SET PASSWORD FOR '{user}'@'{host}' = PASSWORD({lit})")
        self.x("FLUSH PRIVILEGES")

    def drop_user(self, user, host):
        u = "''" if user == "" else f"'{user}'"
        self.x(f"DROP USER {u}@'{host}'")
        self.x("FLUSH PRIVILEGES")

    def lock_to_localhost(self, user, host):
        # create matching localhost + 127.0.0.1 entries cloning grants, then drop the wildcard one
        gr = self.grants(user, host)
        for newhost in ("localhost", "127.0.0.1"):
            try:
                self.x(f"CREATE USER IF NOT EXISTS '{user}'@'{newhost}'")
            except Exception:
                pass
            for g in gr:
                g2 = re.sub(rf"TO\s+`?{re.escape(user)}`?@`?{re.escape(host)}`?",
                            f"TO '{user}'@'{newhost}'", g, flags=re.IGNORECASE)
                if g2.upper().startswith("GRANT") and " TO " in g2.upper():
                    # strip any IDENTIFIED BY / require clauses we can't safely replay
                    g2 = re.split(r"\bIDENTIFIED\b", g2, flags=re.IGNORECASE)[0].strip()
                    try:
                        self.x(g2)
                    except Exception:
                        pass
        self.x("FLUSH PRIVILEGES")

    def drop_database(self, name):
        q = "`" + name.replace("`", "``") + "`"
        self.x(f"DROP DATABASE {q}")

    # ---- audit -------------------------------------------------------------
    def audit(self):
        findings = []
        users = self.users()
        for u in users:
            uh = f"'{u['user'] or '(anonymous)'}'@'{u['host']}'"
            if u["anon"]:
                findings.append(("HIGH", f"Anonymous account {uh}",
                                 "Lets anyone connect and can shadow real logins. Remove it.",
                                 ("drop_user", u["user"], u["host"])))
            if u["host"] == "%" and u["broad"]:
                findings.append(("HIGH", f"{uh} has broad privileges on ANY host",
                                 "Reachable from any host with full power — effectively a second root. "
                                 "Scope it to localhost/127.0.0.1.", None))
            elif u["host"] == "%":
                findings.append(("MEDIUM", f"{uh} accepts connections from ANY host",
                                 "Lock the host to localhost/127.0.0.1 unless a remote server truly needs it.", None))
            if not u["has_pw"] and not u["anon"] and u["plugin"] not in ("unix_socket", "auth_socket"):
                sev = "HIGH" if u["host"] not in ("localhost", "127.0.0.1", "::1") else "MEDIUM"
                findings.append((sev, f"{uh} has no password",
                                 "Set a strong password (remember to update any app/config that uses it).", None))
            if u["grant"] and u["broad"] and u["user"] != "root":
                findings.append(("MEDIUM", f"{uh} holds GRANT + broad privileges",
                                 "If an app uses this account, a leaked config exposes everything. "
                                 "Give apps scoped, GRANT-less users instead.", None))
        # leftover test db
        try:
            if "test" in [d.lower() for d in self.all_databases()]:
                findings.append(("LOW", "'test' database exists",
                                 "Shipped open by default. Drop it if unused.",
                                 ("drop_database", "test", None)))
        except Exception:
            pass
        if not findings:
            findings.append(("OK", "No obvious account issues found", "Nice — the user table looks clean.", None))
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
        findings.sort(key=lambda f: order.get(f[0], 9))
        return findings

    # ---- one-click hardening ----------------------------------------------
    def plan_hardening(self, aggressive: bool = False):
        """Return a list of planned remediation actions without executing them.

        Each item: dict(risk, label, why, action, args).
          risk: "safe"      — reversible / no connectivity impact
                "caution"   — may break an app or remote client if it relied on the account
        Safe actions run automatically; caution actions only run in aggressive mode.
        """
        plan = []
        for u in self.users():
            uh = f"'{u['user'] or '(anonymous)'}'@'{u['host']}'"
            if u["anon"]:
                plan.append({
                    "risk": "safe",
                    "label": f"Drop anonymous account {uh}",
                    "why": "Anonymous logins let anyone connect and can shadow real accounts.",
                    "action": ("drop_user", u["user"], u["host"]),
                })
            elif u["host"] == "%" and u["user"] != "root":
                plan.append({
                    "risk": "caution",
                    "label": f"Lock {uh} to localhost + 127.0.0.1",
                    "why": "Account is reachable from ANY host. Locking it can break a remote "
                           "client that legitimately uses this account, and passwords are not copied.",
                    "action": ("lock_to_localhost", u["user"], u["host"]),
                })
        try:
            if "test" in [d.lower() for d in self.all_databases()]:
                plan.append({
                    "risk": "safe",
                    "label": "Drop the default 'test' database",
                    "why": "Ships world-open by default and is almost never used in production.",
                    "action": ("drop_database", "test", None),
                })
        except Exception:
            pass
        # filter by mode
        return [p for p in plan if aggressive or p["risk"] == "safe"]

    def apply_action(self, action):
        """Execute one planned action tuple. Returns a human-readable result string.

        In simulation mode the statements are recorded (not executed) and the
        wording switches to "Would …" so the report makes the dry-run obvious.
        """
        name, a, b = action
        did = "Would" if self.simulate else "Done:"
        if name == "drop_user":
            self.drop_user(a, b)
            return (f"{did} drop user '{a or '(anonymous)'}'@'{b}'" if self.simulate
                    else f"Dropped user '{a or '(anonymous)'}'@'{b}'")
        if name == "drop_database":
            self.drop_database(a)
            return (f"{did} drop database '{a}'" if self.simulate
                    else f"Dropped database '{a}'")
        if name == "lock_to_localhost":
            self.lock_to_localhost(a, b)
            return (f"{did} lock '{a}'@'{b}' to localhost/127.0.0.1" if self.simulate
                    else f"Locked '{a}'@'{b}' to localhost/127.0.0.1")
        raise ValueError(f"Unknown action: {name}")

    def run_hardening(self, aggressive: bool = False):
        """Apply the hardening plan; return (results, plan) where results = list of (ok, label, msg)."""
        plan = self.plan_hardening(aggressive=aggressive)
        results = []
        for step in plan:
            try:
                msg = self.apply_action(step["action"])
                results.append((True, step["label"], msg))
            except Exception as e:
                results.append((False, step["label"], str(e)))
        return results, plan


# ==============================================================================
# GUI
# ==============================================================================
ctk.set_appearance_mode("dark")


def chip(parent, text, color):
    lbl = ctk.CTkLabel(parent, text=text, font=(MONO, 11, "bold"),
                       text_color=color, fg_color=C["card_hi"], corner_radius=6,
                       padx=8, pady=2)
    return lbl


class Tooltip:
    """Lightweight hover tooltip for any Tk/CTk widget.

    Shows a small dark popup with wrapped explanatory text after a short hover
    delay. Used to attach plain-language "what is this / what does it do"
    guidance to controls without cluttering the layout.
    """

    def __init__(self, widget, text, delay=450, wraplength=320):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self._after = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _=None):
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._after is not None:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _show(self):
        if self._tip is not None or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 18
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        except Exception:
            return
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        self._tip.configure(bg=C["border"])
        lbl = tk.Label(self._tip, text=self.text, justify="left",
                       bg=C["card_hi"], fg=C["text"], font=(MONO, 10),
                       wraplength=self.wraplength, padx=10, pady=8,
                       bd=0, relief="flat")
        lbl.pack(padx=1, pady=1)

    def _hide(self, _=None):
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


def add_tooltip(widget, text):
    """Attach a hover tooltip and return the widget (chainable)."""
    Tooltip(widget, text)
    return widget


class ForgeDB(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("FORGE/DB — Database Security Console")
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.configure(fg_color=C["bg"])

        self.db = DB()
        self.cfg = load_config()
        self.scan_results = []
        self._last_created = None   # (username, password) of the most recent scoped user
        self._brand_images = {}     # keep PhotoImage refs alive

        # --- simulation / dry-run state -------------------------------------
        self.sim_mode = ctk.BooleanVar(value=bool(self.cfg.get("sim_mode", False)))
        self.db.simulate = self.sim_mode.get()
        self.fw_sim_log = []        # recorded firewall commands while simulating

        self._apply_window_icon()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_container()
        self._show("connection")
        self._refresh_connbar()

    # ---- branding ----------------------------------------------------------
    def _apply_window_icon(self):
        ico = resource_path("assets", "img", "icon.ico")
        try:
            if ico.exists():
                self.iconbitmap(default=str(ico))
        except Exception:
            pass

    def _brand_image(self, filename, size):
        """Load an asset as a CTkImage once and cache it. Returns None if unavailable."""
        key = (filename, size)
        if key in self._brand_images:
            return self._brand_images[key]
        path = resource_path("assets", "img", filename)
        img = None
        if path.exists():
            try:
                from PIL import Image
                img = ctk.CTkImage(light_image=Image.open(path),
                                   dark_image=Image.open(path), size=size)
            except Exception:
                img = None
        self._brand_images[key] = img
        return img

    def _brand_image_w(self, filename, width):
        """Load an asset scaled to `width`, preserving aspect ratio. Returns None if unavailable."""
        path = resource_path("assets", "img", filename)
        if not path.exists():
            return None
        try:
            from PIL import Image
            with Image.open(path) as im:
                w, h = im.size
            size = (int(width), max(1, int(round(width * h / w))))
        except Exception:
            return None
        return self._brand_image(filename, size)

    # ---- shared dialogs ----------------------------------------------------
    def confirm_risk(self, title, what, impact, level="caution", extra_confirm=False):
        """Centralised confirmation dialog.

        what    — plain description of the action.
        impact  — what could break / be irreversible.
        level   — "info" | "caution" | "danger".
        Returns True only if the user explicitly confirms (twice for danger/extra).
        """
        tag = {"info": "ℹ", "caution": "⚠", "danger": "⛔"}.get(level, "⚠")
        body = f"{what}\n\nPossible impact:\n{impact}"
        if not messagebox.askyesno(f"{tag} {title}", body):
            return False
        if level == "danger" or extra_confirm:
            if not messagebox.askyesno("⛔ Confirm again",
                                       "This action may be irreversible or disruptive.\n\nProceed?"):
                return False
        return True

    # ---- inline explainers -------------------------------------------------
    INFO_BADGE = {
        "info":    ("ℹ INFO",    "#00e5ff"),
        "safe":    ("✓ SAFE",    "#3ddc84"),
        "caution": ("⚠ CAUTION", "#ffb020"),
        "danger":  ("⛔ DANGER",  "#ff5d6c"),
    }

    def _info_button(self, parent, title, body, level="info"):
        """Return a small clickable 'i' badge that opens a rich explainer popup.

        Use for non-obvious controls so users understand WHAT a thing is, WHAT it
        does, and whether it can break anything before they touch it.
        """
        btn = ctk.CTkButton(parent, text="ⓘ", width=26, height=26, corner_radius=13,
                            font=(MONO, 14, "bold"), fg_color=C["card_hi"],
                            hover_color=C["border"], text_color=C["cyan"],
                            command=lambda: self._show_explainer(title, body, level))
        # one-line teaser on hover; full text on click
        add_tooltip(btn, body if len(body) < 160 else body[:157] + "…")
        return btn

    def _show_explainer(self, title, body, level="info"):
        badge, color = self.INFO_BADGE.get(level, self.INFO_BADGE["info"])
        dlg = ctk.CTkToplevel(self)
        dlg.title(title)
        dlg.geometry("560x380")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(60, dlg.lift)
        top = ctk.CTkFrame(dlg, fg_color="transparent"); top.pack(fill="x", padx=22, pady=(20, 4))
        chip(top, badge, color).pack(side="left")
        ctk.CTkLabel(top, text=title, font=(MONO, 17, "bold"),
                     text_color=C["text"]).pack(side="left", padx=10)
        box = ctk.CTkScrollableFrame(dlg, fg_color=C["card"])
        box.pack(fill="both", expand=True, padx=22, pady=10)
        ctk.CTkLabel(box, text=body, font=(MONO, 12), text_color=C["text"],
                     justify="left", wraplength=480).pack(anchor="w", padx=8, pady=8)
        ctk.CTkButton(dlg, text="Got it", height=36, font=(MONO, 13, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=dlg.destroy).pack(pady=(0, 16))

    # ---- simulation / dry-run ---------------------------------------------
    def _toggle_simulation(self):
        on = bool(self.sim_mode.get())
        self.db.simulate = on
        self.cfg["sim_mode"] = on
        save_config(self.cfg)
        self._refresh_sim_banner()

    def is_sim(self) -> bool:
        return bool(self.sim_mode.get())

    def _record_fw_sim(self, label, cmd_str):
        self.fw_sim_log.append((label, cmd_str))

    def _sim_note(self) -> str:
        return ("\n\nSIMULATION MODE is ON — nothing will actually change. The exact "
                "statements/commands are recorded in the Simulation Log so you can review "
                "them first.") if self.is_sim() else ""

    def _show_sim_log(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Simulation log")
        dlg.geometry("760x560")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(60, dlg.lift)

        head = ctk.CTkFrame(dlg, fg_color="transparent"); head.pack(fill="x", padx=22, pady=(18, 2))
        ctk.CTkLabel(head, text="🧪 Simulation log", font=(MONO, 18, "bold"),
                     text_color=C["gold"]).pack(side="left")
        state = "ON" if self.is_sim() else "OFF"
        ctk.CTkLabel(head, text=f"dry-run is {state}", font=(MONO, 12),
                     text_color=C["amber"] if self.is_sim() else C["muted"]).pack(side="left", padx=12)
        ctk.CTkLabel(dlg, text="Every statement or command below WOULD have run if simulation were off. "
                              "Review them, then turn simulation off to apply for real.",
                     font=(MONO, 11), text_color=C["muted"], wraplength=700,
                     justify="left").pack(anchor="w", padx=22, pady=(2, 8))

        box = ctk.CTkScrollableFrame(dlg, fg_color=C["card"])
        box.pack(fill="both", expand=True, padx=22, pady=6)

        sql = list(self.db.sim_log)
        fw = list(self.fw_sim_log)
        if not sql and not fw:
            ctk.CTkLabel(box, text="Nothing recorded yet.\n\nTurn on Simulation mode, then try an action "
                                  "(drop a user, lock a host, rotate a password, add a firewall rule) — "
                                  "the would-be statements appear here.",
                         font=(MONO, 12), text_color=C["muted"], justify="left").pack(anchor="w", padx=10, pady=10)
        else:
            if sql:
                ctk.CTkLabel(box, text="DATABASE statements", font=(MONO, 12, "bold"),
                             text_color=C["cyan"]).pack(anchor="w", padx=8, pady=(8, 2))
                for i, s in enumerate(sql, 1):
                    ctk.CTkLabel(box, text=f"{i:>2}.  {s}", font=(MONO, 11), text_color=C["text"],
                                 justify="left", wraplength=680).pack(anchor="w", padx=12, pady=1)
            if fw:
                ctk.CTkLabel(box, text="FIREWALL / SYSTEM commands", font=(MONO, 12, "bold"),
                             text_color=C["gold"]).pack(anchor="w", padx=8, pady=(12, 2))
                for i, (label, cmd) in enumerate(fw, 1):
                    ctk.CTkLabel(box, text=f"{i:>2}.  {label}", font=(MONO, 11, "bold"),
                                 text_color=C["text"], justify="left", wraplength=680).pack(anchor="w", padx=12, pady=(4, 0))
                    ctk.CTkLabel(box, text=f"      {cmd}", font=(MONO, 10), text_color=C["muted"],
                                 justify="left", wraplength=680).pack(anchor="w", padx=12)

        btns = ctk.CTkFrame(dlg, fg_color="transparent"); btns.pack(fill="x", padx=22, pady=(4, 16))
        ctk.CTkButton(btns, text="Export log", height=36, font=(MONO, 12),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=self._export_sim_log).pack(side="left")
        ctk.CTkButton(btns, text="Clear log", height=36, font=(MONO, 12),
                      fg_color="transparent", border_width=1, border_color=C["red"],
                      text_color=C["red"], hover_color="#3a1620",
                      command=lambda: (self.db.clear_sim_log(), self.fw_sim_log.clear(),
                                       dlg.destroy(), self._show_sim_log())).pack(side="left", padx=8)
        ctk.CTkButton(btns, text="Close", height=36, font=(MONO, 13, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=dlg.destroy).pack(side="right")

    def _export_sim_log(self):
        if not self.db.sim_log and not self.fw_sim_log:
            messagebox.showinfo("FORGE/DB", "The simulation log is empty.")
            return
        try:
            ensure_reports_dir()
            ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            path = REPORTS_DIR / f"forgedb-simulation-{ts}.txt"
            lines = ["FORGE/DB simulation log", f"generated: {datetime.datetime.now().isoformat(timespec='seconds')}", ""]
            if self.db.sim_log:
                lines.append("# DATABASE statements")
                lines += [f"{i}. {s}" for i, s in enumerate(self.db.sim_log, 1)]
                lines.append("")
            if self.fw_sim_log:
                lines.append("# FIREWALL / SYSTEM commands")
                for i, (label, cmd) in enumerate(self.fw_sim_log, 1):
                    lines.append(f"{i}. {label}")
                    lines.append(f"   {cmd}")
            path.write_text("\n".join(lines), encoding="utf-8")
        except Exception as e:
            messagebox.showerror("FORGE/DB", f"Could not export log:\n{e}")
            return
        if messagebox.askyesno("FORGE/DB", f"Saved:\n{path.name}\n\nin {REPORTS_DIR}\n\nOpen the folder?"):
            try:
                os.startfile(str(REPORTS_DIR))  # type: ignore[attr-defined]
            except Exception:
                pass

    # ---- layout ------------------------------------------------------------
    def _build_sidebar(self):
        side = ctk.CTkFrame(self, width=210, corner_radius=0, fg_color=C["panel"])
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        logo = self._brand_image("logo.png", (150, 60))
        if logo is not None:
            ctk.CTkLabel(side, image=logo, text="").pack(pady=(20, 4), padx=20, anchor="w")
            ctk.CTkLabel(side, text="DB SECURITY CONSOLE", font=(MONO, 10, "bold"),
                         text_color=C["gold"]).pack(pady=(0, 22), padx=20, anchor="w")
        else:
            ctk.CTkLabel(side, text="FORGE/DB", font=(MONO, 24, "bold"),
                         text_color=C["cyan"]).pack(pady=(26, 0), padx=20, anchor="w")
            ctk.CTkLabel(side, text="DB SECURITY CONSOLE", font=(MONO, 10, "bold"),
                         text_color=C["gold"]).pack(pady=(0, 24), padx=20, anchor="w")

        self.nav_buttons = {}
        items = [("connection", "◇  Connection"),
                 ("audit", "▲  Security Audit"),
                 ("users", "◈  Users"),
                 ("creds", "⚙  App Credentials"),
                 ("network", "⇄  Network & Ports"),
                 ("guide", "❔  Guide & Help"),
                 ("settings", "⋯  Settings")]
        for key, label in items:
            b = ctk.CTkButton(side, text=label, anchor="w", height=42,
                              font=(MONO, 14), corner_radius=8,
                              fg_color="transparent", text_color=C["text"],
                              hover_color=C["card_hi"],
                              command=lambda k=key: self._show(k))
            b.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = b

        self.status_dot = ctk.CTkLabel(side, text="● disconnected", font=(MONO, 12, "bold"),
                                       text_color=C["red"])
        self.status_dot.pack(side="bottom", padx=20, pady=(6, 16), anchor="w")

        # --- simulation controls (above the status dot) --------------------
        simwrap = ctk.CTkFrame(side, fg_color=C["card"], corner_radius=8,
                               border_width=1, border_color=C["border"])
        simwrap.pack(side="bottom", fill="x", padx=12, pady=(0, 4))
        sw = ctk.CTkSwitch(simwrap, text="Simulation mode", variable=self.sim_mode,
                           command=self._toggle_simulation, font=(MONO, 12, "bold"),
                           progress_color=C["amber"], button_color=C["text"],
                           text_color=C["text"])
        sw.pack(anchor="w", padx=10, pady=(10, 4))
        add_tooltip(sw, "DRY-RUN. When ON, every change (drop user, lock host, rotate "
                        "password, firewall rule) is only PREVIEWED and recorded — nothing "
                        "is actually applied. Turn it off to make real changes.")
        ctk.CTkButton(simwrap, text="☰ View simulation log", height=30, font=(MONO, 11),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["gold"], hover_color=C["card_hi"],
                      command=self._show_sim_log).pack(fill="x", padx=10, pady=(0, 10))

    def _build_container(self):
        outer = ctk.CTkFrame(self, corner_radius=0, fg_color=C["bg"])
        outer.grid(row=0, column=1, sticky="nsew")
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(2, weight=1)

        # Branding header banner (Digital-Header.png) across the top of the content area.
        header = self._brand_image_w("Digital-Header.png", 760)
        if header is not None:
            hbar = ctk.CTkFrame(outer, fg_color=C["panel"], corner_radius=0)
            hbar.grid(row=0, column=0, sticky="ew")
            ctk.CTkLabel(hbar, image=header, text="").pack(padx=12, pady=8)

        # Simulation banner (shown only while dry-run is active).
        self.sim_banner = ctk.CTkFrame(outer, fg_color=C["amber"], corner_radius=0)
        self.sim_banner_lbl = ctk.CTkLabel(
            self.sim_banner,
            text="🧪  SIMULATION MODE — changes are previewed only, nothing is applied.",
            font=(MONO, 12, "bold"), text_color="#241a00")
        self.sim_banner_lbl.pack(side="left", padx=16, pady=6)
        ctk.CTkButton(self.sim_banner, text="View log", width=90, height=24, font=(MONO, 11, "bold"),
                      fg_color="#241a00", text_color=C["gold"], hover_color="#3a2c00",
                      command=self._show_sim_log).pack(side="right", padx=12, pady=4)

        self.container = ctk.CTkFrame(outer, corner_radius=0, fg_color=C["bg"])
        self.container.grid(row=2, column=0, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for key, builder in (("connection", self._page_connection),
                             ("audit", self._page_audit),
                             ("users", self._page_users),
                             ("creds", self._page_creds),
                             ("network", self._page_network),
                             ("guide", self._page_guide),
                             ("settings", self._page_settings)):
            f = ctk.CTkFrame(self.container, fg_color=C["bg"])
            f.grid(row=0, column=0, sticky="nsew")
            builder(f)
            self.frames[key] = f
        self._refresh_sim_banner()

    def _refresh_sim_banner(self):
        if self.is_sim():
            self.sim_banner.grid(row=1, column=0, sticky="ew")
        else:
            self.sim_banner.grid_remove()

    def _show(self, key):
        self.frames[key].tkraise()
        for k, b in self.nav_buttons.items():
            b.configure(fg_color=C["card_hi"] if k == key else "transparent",
                        text_color=C["cyan"] if k == key else C["text"])

    def _header(self, parent, title, subtitle):
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.pack(fill="x", padx=28, pady=(24, 8))
        ctk.CTkLabel(bar, text=title, font=(MONO, 22, "bold"),
                     text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(bar, text=subtitle, font=(MONO, 12),
                     text_color=C["muted"]).pack(anchor="w", pady=(2, 0))

    def _refresh_connbar(self):
        if self.db.connected:
            self.status_dot.configure(text=f"● connected", text_color=C["green"])
        else:
            self.status_dot.configure(text="● disconnected", text_color=C["red"])

    # ======================================================================
    # PAGE: Connection
    # ======================================================================
    def _page_connection(self, p):
        # Branding backdrop (DS5.png) — placed behind the page content as a watermark.
        bg = self._brand_image_w("DS5.png", 460)
        if bg is not None:
            bglbl = ctk.CTkLabel(p, image=bg, text="")
            bglbl.place(relx=1.0, rely=1.0, x=-12, y=-12, anchor="se")
            bglbl.lower()
        self._header(p, "Connection", "Connect to MySQL/MariaDB on this machine. Password is held in memory only.")
        card = ctk.CTkFrame(p, fg_color=C["card"], corner_radius=12, border_width=1, border_color=C["border"])
        card.pack(fill="x", padx=28, pady=10)

        self.e_host = self._field(card, "Host", self.cfg.get("host", "127.0.0.1"))
        self.e_port = self._field(card, "Port", str(self.cfg.get("port", "3306")))
        self.e_user = self._field(card, "User", self.cfg.get("user", "root"))
        self.e_pass = self._field(card, "Password", "", show="•")

        if not PYMYSQL_OK:
            ctk.CTkLabel(card, text="PyMySQL not installed — run:  pip install pymysql",
                         text_color=C["red"], font=(MONO, 12)).pack(anchor="w", padx=18, pady=(0, 6))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(8, 18))
        ctk.CTkButton(row, text="Connect", width=140, height=40, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=self._do_connect).pack(side="left")
        ctk.CTkButton(row, text="Disconnect", width=120, height=40, font=(MONO, 14),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=self._do_disconnect).pack(side="left", padx=10)
        self.conn_status = ctk.CTkLabel(card, text="", font=(MONO, 13), text_color=C["muted"])
        self.conn_status.pack(anchor="w", padx=18, pady=(0, 16))

        tip = ("Tip: connect as root (or another admin) to manage users and run the audit.\n"
               "Keep this app outside C:\\xampp\\htdocs and only run it over RDP.")
        ctk.CTkLabel(p, text=tip, font=(MONO, 11), text_color=C["muted"], justify="left").pack(anchor="w", padx=30, pady=8)

    def _field(self, parent, label, value, show=None):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="x", padx=18, pady=(14, 0))
        ctk.CTkLabel(wrap, text=label, width=90, anchor="w",
                     font=(MONO, 13), text_color=C["muted"]).pack(side="left")
        e = ctk.CTkEntry(wrap, font=(MONO, 14), height=38, fg_color=C["bg"],
                         border_color=C["border"], text_color=C["text"])
        if show:
            e.configure(show=show)
        e.insert(0, value)
        e.pack(side="left", fill="x", expand=True)
        return e

    def _do_connect(self):
        if not PYMYSQL_OK:
            messagebox.showerror("FORGE/DB", "PyMySQL is not installed.\n\npip install pymysql")
            return
        try:
            ver = self.db.connect(self.e_host.get().strip(), self.e_port.get().strip(),
                                  self.e_user.get().strip(), self.e_pass.get())
            self.conn_status.configure(text=f"Connected — MariaDB/MySQL {ver}", text_color=C["green"])
            self.cfg.update({"host": self.e_host.get().strip(), "port": self.e_port.get().strip(),
                             "user": self.e_user.get().strip()})
            save_config(self.cfg)
            self._refresh_connbar()
            self._load_users()
            self._run_audit()
        except Exception as e:
            self.conn_status.configure(text=f"Connection failed: {e}", text_color=C["red"])
            self._refresh_connbar()

    def _do_disconnect(self):
        self.db.close()
        self.conn_status.configure(text="Disconnected.", text_color=C["muted"])
        self._refresh_connbar()

    def _guard(self):
        if not self.db.connected:
            messagebox.showwarning("FORGE/DB", "Connect to the database first (Connection tab).")
            return False
        return True

    # ======================================================================
    # PAGE: Security Audit
    # ======================================================================
    def _page_audit(self, p):
        self._header(p, "Security Audit", "Automated checks against your MySQL accounts and defaults.")
        bar = ctk.CTkFrame(p, fg_color="transparent")
        bar.pack(fill="x", padx=28)
        ctk.CTkButton(bar, text="Run audit", width=130, height=38, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=self._run_audit).pack(side="left")
        ctk.CTkButton(bar, text="⛨ Full hardening", width=160, height=38, font=(MONO, 13, "bold"),
                      fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                      command=self._full_hardening_dialog).pack(side="left", padx=8)
        self._info_button(bar,
                          "Full hardening",
                          "Runs a batch of the safest fixes at once: removing anonymous logins and the "
                          "leftover 'test' database (SAFE), and optionally locking wildcard '%' hosts to "
                          "localhost (CAUTION — could cut off a remote client). You always see the plan "
                          "first. Tip: flip on Simulation mode to preview the exact SQL before applying.",
                          level="caution").pack(side="left", padx=(0, 8))
        ctk.CTkButton(bar, text="⤓ Export report", width=150, height=38, font=(MONO, 13),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=self._export_report).pack(side="left")
        self.audit_summary = ctk.CTkLabel(bar, text="", font=(MONO, 13), text_color=C["muted"])
        self.audit_summary.pack(side="left", padx=16)

        # Security score card (informational only — never changes anything).
        self.score_card = ctk.CTkFrame(p, fg_color=C["card"], corner_radius=12,
                                       border_width=1, border_color=C["border"])
        self.score_card.pack(fill="x", padx=28, pady=(12, 2))
        self.score_grade = ctk.CTkLabel(self.score_card, text="—", font=(MONO, 40, "bold"),
                                        text_color=C["muted"], width=90)
        self.score_grade.pack(side="left", padx=(20, 10), pady=14)
        scol = ctk.CTkFrame(self.score_card, fg_color="transparent"); scol.pack(side="left", fill="x", expand=True, pady=14)
        self.score_value = ctk.CTkLabel(scol, text="Run an audit to score your posture",
                                        font=(MONO, 15, "bold"), text_color=C["text"], anchor="w")
        self.score_value.pack(anchor="w")
        self.score_break = ctk.CTkLabel(scol, text="0–100, weighted by severity of open findings",
                                        font=(MONO, 11), text_color=C["muted"], anchor="w")
        self.score_break.pack(anchor="w", pady=(2, 0))
        self._info_button(self.score_card,
                          "How the security score works",
                          "A simple 0–100 health number for your database accounts and defaults.\n\n"
                          "It starts at 100 and subtracts points for each open finding: about 28 for a "
                          "HIGH, 12 for a MEDIUM, 4 for a LOW. A→F grade is just a friendly label.\n\n"
                          "It is READ-ONLY — calculating it changes nothing. Fix issues (or preview the "
                          "fixes in Simulation mode) and re-run the audit to watch it improve.",
                          level="info").pack(side="right", padx=16)

        self.audit_list = ctk.CTkScrollableFrame(p, fg_color=C["bg"])
        self.audit_list.pack(fill="both", expand=True, padx=24, pady=12)

    def _run_audit(self):
        if not self.db.connected:
            return
        for w in self.audit_list.winfo_children():
            w.destroy()
        try:
            findings = self.db.audit()
        except Exception as e:
            self.audit_summary.configure(text=f"Audit error: {e}", text_color=C["red"])
            return
        counts = {}
        for sev, *_ in findings:
            counts[sev] = counts.get(sev, 0) + 1
        summary = "   ".join(f"{k}: {v}" for k, v in counts.items())
        self.audit_summary.configure(text=summary, text_color=C["text"])

        # update the score card
        sc = compute_security_score(findings)
        self.score_grade.configure(text=sc["grade"], text_color=sc["color"])
        self.score_value.configure(text=f"Security score: {sc['score']} / 100   (grade {sc['grade']})",
                                   text_color=sc["color"])
        cb = sc["counts"]
        self.score_break.configure(
            text=f"open findings — HIGH: {cb['HIGH']}   MEDIUM: {cb['MEDIUM']}   LOW: {cb['LOW']}",
            text_color=C["muted"])

        for sev, title, detail, fix in findings:
            card = ctk.CTkFrame(self.audit_list, fg_color=C["card"], corner_radius=10,
                                border_width=1, border_color=C["border"])
            card.pack(fill="x", pady=5, padx=2)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=14, pady=(12, 2))
            chip(top, sev, SEV_COLORS.get(sev, C["muted"])).pack(side="left")
            ctk.CTkLabel(top, text=title, font=(MONO, 14, "bold"),
                         text_color=C["text"]).pack(side="left", padx=10)
            if fix:
                ctk.CTkButton(top, text="Fix", width=64, height=28, font=(MONO, 12, "bold"),
                              fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                              command=lambda f=fix, t=title: self._apply_fix(f, t)).pack(side="right")
            ctk.CTkLabel(card, text=detail, font=(MONO, 12), text_color=C["muted"],
                         justify="left", wraplength=820).pack(anchor="w", padx=14, pady=(0, 12))

    def _apply_fix(self, fix, title):
        action, a, b = fix
        sim = self.is_sim()
        impact = ("Dropping a user or database is permanent and cannot be undone. "
                  "Any app still using it will stop working until reconfigured.")
        if not self.confirm_risk(
                "Apply fix" + (" (simulation)" if sim else ""),
                f"{title}\n\nThis will run: {action} {a or ''}" + self._sim_note(),
                impact,
                level="info" if sim else "danger"):
            return
        try:
            if action == "drop_user":
                self.db.drop_user(a, b)
            elif action == "drop_database":
                self.db.drop_database(a)
            self._run_audit()
            self._load_users()
            if sim:
                messagebox.showinfo("FORGE/DB — simulation",
                                    "Recorded (not applied). Open the Simulation Log to review the exact SQL.")
        except Exception as e:
            messagebox.showerror("FORGE/DB", f"Could not apply fix:\n{e}")

    def _export_report(self):
        if not self._guard():
            return
        try:
            findings = self.db.audit()
            users = self.db.users()
            report = build_report(self.db.info, findings, users, self.scan_results)
            jpath, cpath = timestamped_report_paths()
            export_report_json(report, jpath)
            export_report_csv(report, cpath)
        except Exception as e:
            messagebox.showerror("FORGE/DB", f"Could not export report:\n{e}")
            return
        if messagebox.askyesno("FORGE/DB",
                               f"Audit report saved:\n\n{jpath.name}\n{cpath.name}\n\n"
                               f"in {REPORTS_DIR}\n\nOpen the reports folder now?"):
            try:
                os.startfile(str(REPORTS_DIR))  # type: ignore[attr-defined]
            except Exception:
                pass

    def _full_hardening_dialog(self):
        if not self._guard():
            return
        dlg = ctk.CTkToplevel(self)
        dlg.title("One-click hardening")
        dlg.geometry("640x640")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(80, dlg.lift)

        ctk.CTkLabel(dlg, text="One-click hardening", font=(MONO, 18, "bold"),
                     text_color=C["gold"]).pack(anchor="w", padx=22, pady=(20, 2))
        ctk.CTkLabel(dlg, text="Review the planned actions before applying. SAFE actions are reversible in "
                              "effect and won't cut off connectivity. CAUTION actions can break an app or a "
                              "remote client — they only run when 'aggressive mode' is enabled.",
                     font=(MONO, 11), text_color=C["muted"], wraplength=580, justify="left").pack(anchor="w", padx=22)

        aggressive = ctk.CTkCheckBox(dlg, text="Aggressive mode (also apply CAUTION actions)",
                                     font=(MONO, 12), text_color=C["amber"])
        aggressive.pack(anchor="w", padx=22, pady=(12, 6))

        plan_box = ctk.CTkScrollableFrame(dlg, fg_color=C["card"], height=300)
        plan_box.pack(fill="both", expand=True, padx=22, pady=6)
        msg = ctk.CTkLabel(dlg, text="", font=(MONO, 11), text_color=C["muted"],
                           wraplength=580, justify="left")
        msg.pack(anchor="w", padx=22, pady=6)

        def refresh_plan():
            for w in plan_box.winfo_children():
                w.destroy()
            try:
                plan = self.db.plan_hardening(aggressive=bool(aggressive.get()))
            except Exception as e:
                ctk.CTkLabel(plan_box, text=f"Could not build plan: {e}",
                             text_color=C["red"], font=(MONO, 12)).pack(anchor="w", pady=8)
                return
            if not plan:
                ctk.CTkLabel(plan_box, text="Nothing to harden — looks clean already.",
                             text_color=C["green"], font=(MONO, 12)).pack(anchor="w", pady=8)
                return
            for step in plan:
                color = C["green"] if step["risk"] == "safe" else C["amber"]
                row = ctk.CTkFrame(plan_box, fg_color=C["row_a"], corner_radius=6)
                row.pack(fill="x", pady=3, padx=2)
                chip(row, step["risk"].upper(), color).pack(side="left", padx=8, pady=8)
                txt = ctk.CTkFrame(row, fg_color="transparent"); txt.pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(txt, text=step["label"], font=(MONO, 12, "bold"),
                             text_color=C["text"], anchor="w").pack(anchor="w")
                ctk.CTkLabel(txt, text=step["why"], font=(MONO, 10), text_color=C["muted"],
                             anchor="w", wraplength=440, justify="left").pack(anchor="w")

        def do_apply():
            agg = bool(aggressive.get())
            sim = self.is_sim()
            warn = ("This will apply EVERY action listed above, including CAUTION items that may "
                    "break apps or remote clients.") if agg else \
                   ("This will apply the SAFE actions listed above. They are reversible in effect "
                    "but dropping anonymous users / the test DB is still permanent.")
            warn += self._sim_note()
            level = ("info" if sim else ("danger" if agg else "caution"))
            verb = "Preview the listed actions (simulation)." if sim else "Run the listed remediation actions now."
            if not self.confirm_risk("Apply hardening plan" + (" (simulation)" if sim else ""),
                                     verb, warn, level=level):
                return
            try:
                results, _ = self.db.run_hardening(aggressive=agg)
            except Exception as e:
                msg.configure(text=f"✗ {e}", text_color=C["red"]); return
            ok = sum(1 for r in results if r[0])
            bad = len(results) - ok
            lines = [("✓ " if r[0] else "✗ ") + r[1] + (f"  — {r[2]}" if not r[0] else "") for r in results]
            head = (f"SIMULATED {ok} action(s) — nothing applied. Review them in the Simulation Log.\n\n"
                    if sim else f"Applied {ok} action(s), {bad} failed.\n\n")
            msg.configure(text=head + "\n".join(lines),
                          text_color=C["amber"] if sim else (C["green"] if bad == 0 else C["amber"]))
            self._run_audit(); self._load_users(); refresh_plan()

        btns = ctk.CTkFrame(dlg, fg_color="transparent"); btns.pack(fill="x", padx=22, pady=(4, 16))
        ctk.CTkButton(btns, text="Preview / refresh plan", height=38, font=(MONO, 13),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=refresh_plan).pack(side="left")
        ctk.CTkButton(btns, text="Apply now", height=38, font=(MONO, 14, "bold"),
                      fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                      command=do_apply).pack(side="right")

        aggressive.configure(command=refresh_plan)
        refresh_plan()

    # ======================================================================
    # PAGE: Users
    # ======================================================================
    def _page_users(self, p):
        self._header(p, "Users", "Every MySQL account. Risky entries are flagged.")
        bar = ctk.CTkFrame(p, fg_color="transparent")
        bar.pack(fill="x", padx=28)
        ctk.CTkButton(bar, text="↻ Refresh", width=110, height=38, font=(MONO, 13),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=self._load_users).pack(side="left")
        ctk.CTkButton(bar, text="+ Create scoped app user", width=210, height=38, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=self._create_user_dialog).pack(side="left", padx=10)

        head = ctk.CTkFrame(p, fg_color=C["panel"], corner_radius=8)
        head.pack(fill="x", padx=24, pady=(12, 0))
        for txt, w in (("USER", 160), ("HOST", 130), ("PASSWORD", 110), ("PRIVILEGES", 230), ("", 220)):
            ctk.CTkLabel(head, text=txt, width=w, anchor="w", font=(MONO, 11, "bold"),
                         text_color=C["gold"]).pack(side="left", padx=6, pady=8)

        self.users_list = ctk.CTkScrollableFrame(p, fg_color=C["bg"])
        self.users_list.pack(fill="both", expand=True, padx=24, pady=(4, 14))

    def _load_users(self):
        if not self.db.connected:
            return
        for w in self.users_list.winfo_children():
            w.destroy()
        try:
            users = self.db.users()
        except Exception as e:
            ctk.CTkLabel(self.users_list, text=f"Could not read users: {e}",
                         text_color=C["red"], font=(MONO, 13)).pack(anchor="w", pady=8)
            return
        for i, u in enumerate(users):
            risky = u["anon"] or (u["host"] == "%") or (not u["has_pw"] and u["plugin"] not in ("unix_socket", "auth_socket"))
            row = ctk.CTkFrame(self.users_list, fg_color=C["row_b"] if i % 2 else C["row_a"],
                               corner_radius=6, border_width=1,
                               border_color=C["red"] if risky else C["border"])
            row.pack(fill="x", pady=2)

            uname = u["user"] if u["user"] else "(anonymous)"
            ctk.CTkLabel(row, text=uname, width=160, anchor="w", font=(MONO, 13, "bold"),
                         text_color=C["red"] if u["anon"] else C["text"]).pack(side="left", padx=6, pady=8)
            hcolor = C["amber"] if u["host"] == "%" else C["text"]
            ctk.CTkLabel(row, text=u["host"], width=130, anchor="w", font=(MONO, 13),
                         text_color=hcolor).pack(side="left", padx=6)
            pw_txt = "yes" if u["has_pw"] else ("OS-auth" if u["plugin"] in ("unix_socket", "auth_socket") else "NONE")
            pw_col = C["green"] if u["has_pw"] else (C["muted"] if "OS" in pw_txt else C["red"])
            ctk.CTkLabel(row, text=pw_txt, width=110, anchor="w", font=(MONO, 13),
                         text_color=pw_col).pack(side="left", padx=6)
            priv_txt = u["priv"] + ("  +GRANT" if u["grant"] else "")
            pcol = C["amber"] if (u["broad"] and u["host"] == "%") else C["text"]
            ctk.CTkLabel(row, text=priv_txt, width=230, anchor="w", font=(MONO, 12),
                         text_color=pcol).pack(side="left", padx=6)

            actions = ctk.CTkFrame(row, fg_color="transparent")
            actions.pack(side="left", padx=4)
            ctk.CTkButton(actions, text="Password", width=84, height=26, font=(MONO, 11),
                          fg_color=C["card_hi"], hover_color=C["border"], text_color=C["text"],
                          command=lambda x=u: self._change_pw_dialog(x)).pack(side="left", padx=2)
            if u["host"] == "%":
                ctk.CTkButton(actions, text="Lock→local", width=92, height=26, font=(MONO, 11),
                              fg_color=C["card_hi"], hover_color=C["border"], text_color=C["gold"],
                              command=lambda x=u: self._lock_host(x)).pack(side="left", padx=2)
            ctk.CTkButton(actions, text="Drop", width=54, height=26, font=(MONO, 11),
                          fg_color="transparent", border_width=1, border_color=C["red"],
                          text_color=C["red"], hover_color="#3a1620",
                          command=lambda x=u: self._drop_user(x)).pack(side="left", padx=2)

    def _create_user_dialog(self):
        if not self._guard():
            return
        dlg = ctk.CTkToplevel(self)
        dlg.title("Create scoped app user")
        dlg.geometry("520x620")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self)
        dlg.after(80, dlg.lift)

        ctk.CTkLabel(dlg, text="Create scoped app user", font=(MONO, 18, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", padx=22, pady=(20, 4))
        ctk.CTkLabel(dlg, text="A least-privilege user limited to one database — what each app should use.",
                     font=(MONO, 11), text_color=C["muted"], wraplength=470, justify="left").pack(anchor="w", padx=22)

        name_e = self._field(dlg, "Username", "")
        ctk.CTkLabel(dlg, text="Database", anchor="w", font=(MONO, 13), text_color=C["muted"]).pack(anchor="w", padx=22, pady=(14, 2))
        try:
            dbs = self.db.databases() or self.db.all_databases()
        except Exception:
            dbs = []
        db_var = ctk.StringVar(value=dbs[0] if dbs else "")
        ctk.CTkOptionMenu(dlg, values=dbs or ["(no databases)"], variable=db_var,
                          font=(MONO, 13), fg_color=C["card"], button_color=C["cyan_dim"]).pack(fill="x", padx=22)

        ctk.CTkLabel(dlg, text="Hosts", anchor="w", font=(MONO, 13), text_color=C["muted"]).pack(anchor="w", padx=22, pady=(14, 2))
        h_local = ctk.CTkCheckBox(dlg, text="localhost", font=(MONO, 13))
        h_local.select(); h_local.pack(anchor="w", padx=30)
        h_ip = ctk.CTkCheckBox(dlg, text="127.0.0.1", font=(MONO, 13))
        h_ip.select(); h_ip.pack(anchor="w", padx=30, pady=4)
        ctk.CTkLabel(dlg, text="(both recommended — Windows apps use either depending on the driver)",
                     font=(MONO, 10), text_color=C["muted"]).pack(anchor="w", padx=30)

        ctk.CTkLabel(dlg, text="Privileges", anchor="w", font=(MONO, 13), text_color=C["muted"]).pack(anchor="w", padx=22, pady=(14, 2))
        priv_vars = {}
        crud_row = ctk.CTkFrame(dlg, fg_color="transparent"); crud_row.pack(anchor="w", padx=30)
        for pv in CRUD_PRIVS:
            cb = ctk.CTkCheckBox(crud_row, text=pv, font=(MONO, 12), width=90)
            cb.select(); cb.pack(side="left", padx=2)
            priv_vars[pv] = cb
        ctk.CTkLabel(dlg, text="Schema (only if the app runs its own migrations):",
                     font=(MONO, 11), text_color=C["muted"]).pack(anchor="w", padx=30, pady=(8, 2))
        sch_row = ctk.CTkFrame(dlg, fg_color="transparent"); sch_row.pack(anchor="w", padx=30)
        for pv in SCHEMA_PRIVS:
            cb = ctk.CTkCheckBox(sch_row, text=pv, font=(MONO, 12), width=92)
            cb.pack(side="left", padx=2)
            priv_vars[pv] = cb

        out = ctk.CTkLabel(dlg, text="", font=(MONO, 12), text_color=C["muted"], wraplength=470, justify="left")
        out.pack(anchor="w", padx=22, pady=10)

        def do_create():
            hosts = []
            if h_local.get(): hosts.append("localhost")
            if h_ip.get(): hosts.append("127.0.0.1")
            privs = [p for p, cb in priv_vars.items() if cb.get()]
            try:
                if not hosts:
                    raise ValueError("Pick at least one host.")
                pw = self.db.create_scoped_user(name_e.get().strip(), hosts, db_var.get(), privs)
                out.configure(text=f"✓ Created '{name_e.get().strip()}' on {', '.join(hosts)}\n\n"
                                   f"Password (copy it now — not stored):\n{pw}", text_color=C["green"])
                self._last_created = (name_e.get().strip(), pw)
                self._load_users()
            except Exception as e:
                out.configure(text=f"✗ {e}", text_color=C["red"])

        ctk.CTkButton(dlg, text="Create user", height=40, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=do_create).pack(fill="x", padx=22, pady=(6, 18))

    def _change_pw_dialog(self, u):
        if not self._guard():
            return
        dlg = ctk.CTkToplevel(self)
        dlg.title("Change password")
        dlg.geometry("480x300")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(80, dlg.lift)
        ctk.CTkLabel(dlg, text=f"Password for '{u['user']}'@'{u['host']}'", font=(MONO, 16, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", padx=22, pady=(20, 8))
        pw_e = self._field(dlg, "New", generate_password())
        warn = ("Reminder: if an app or phpMyAdmin connects with this account, update its\n"
                "config to the new password or it will fail to connect.")
        ctk.CTkLabel(dlg, text=warn, font=(MONO, 11), text_color=C["amber"], justify="left").pack(anchor="w", padx=22, pady=10)
        msg = ctk.CTkLabel(dlg, text="", font=(MONO, 12), text_color=C["muted"]); msg.pack(anchor="w", padx=22)

        def do_set():
            try:
                self.db.set_password(u["user"], u["host"], pw_e.get())
                msg.configure(text="✓ Password updated.", text_color=C["green"])
                self._load_users()
            except Exception as e:
                msg.configure(text=f"✗ {e}", text_color=C["red"])

        ctk.CTkButton(dlg, text="Set password", height=38, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=do_set).pack(fill="x", padx=22, pady=16)

    def _lock_host(self, u):
        if not self._guard():
            return
        if not messagebox.askyesno("FORGE/DB",
                                    f"Recreate '{u['user']}' on localhost + 127.0.0.1 (cloning its grants)\n"
                                    f"and drop '{u['user']}'@'%'?\n\n"
                                    "Make sure no remote server needs this account first.\n"
                                    "Note: passwords are not copied — set one afterward."):
            return
        try:
            self.db.lock_to_localhost(u["user"], u["host"])
            messagebox.showinfo("FORGE/DB", "Done. Set a password on the new entries, then update your apps.")
            self._load_users(); self._run_audit()
        except Exception as e:
            messagebox.showerror("FORGE/DB", f"Could not lock host:\n{e}")

    def _drop_user(self, u):
        if not self._guard():
            return
        uname = u["user"] if u["user"] else "(anonymous)"
        if not messagebox.askyesno("FORGE/DB", f"Drop '{uname}'@'{u['host']}'?\nThis cannot be undone."):
            return
        try:
            self.db.drop_user(u["user"], u["host"])
            self._load_users(); self._run_audit()
        except Exception as e:
            messagebox.showerror("FORGE/DB", f"Could not drop user:\n{e}")

    # ======================================================================
    # PAGE: App Credentials (htdocs scanner)
    # ======================================================================
    def _page_creds(self, p):
        self._header(p, "App Credentials", "Scan htdocs for DB connections and rotate them safely (files are backed up first).")
        bar = ctk.CTkFrame(p, fg_color="transparent")
        bar.pack(fill="x", padx=28)
        self.htdocs_e = ctk.CTkEntry(bar, font=(MONO, 13), height=38, width=420,
                                     fg_color=C["bg"], border_color=C["border"], text_color=C["text"])
        self.htdocs_e.insert(0, self.cfg.get("htdocs", r"C:\xampp\htdocs"))
        self.htdocs_e.pack(side="left")
        ctk.CTkButton(bar, text="Browse", width=84, height=38, font=(MONO, 12),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["text"], hover_color=C["card_hi"],
                      command=self._browse_htdocs).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Scan", width=100, height=38, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=self._do_scan).pack(side="left")
        ctk.CTkButton(bar, text="⟳ Bulk rotate", width=130, height=38, font=(MONO, 13, "bold"),
                      fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                      command=self._bulk_rotate_dialog).pack(side="left", padx=8)
        self.scan_summary = ctk.CTkLabel(bar, text="", font=(MONO, 12), text_color=C["muted"])
        self.scan_summary.pack(side="left", padx=14)

        head = ctk.CTkFrame(p, fg_color=C["panel"], corner_radius=8)
        head.pack(fill="x", padx=24, pady=(12, 0))
        for txt, w in (("APP", 150), ("KIND", 130), ("USER", 120), ("DATABASE", 140), ("PW", 80), ("", 120)):
            ctk.CTkLabel(head, text=txt, width=w, anchor="w", font=(MONO, 11, "bold"),
                         text_color=C["gold"]).pack(side="left", padx=6, pady=8)

        self.creds_list = ctk.CTkScrollableFrame(p, fg_color=C["bg"])
        self.creds_list.pack(fill="both", expand=True, padx=24, pady=(4, 14))

    def _browse_htdocs(self):
        d = filedialog.askdirectory(initialdir=self.htdocs_e.get() or "/")
        if d:
            self.htdocs_e.delete(0, "end"); self.htdocs_e.insert(0, d)

    def _do_scan(self):
        root = self.htdocs_e.get().strip()
        if not os.path.isdir(root):
            messagebox.showwarning("FORGE/DB", "That folder doesn't exist.")
            return
        self.cfg["htdocs"] = root; save_config(self.cfg)
        for w in self.creds_list.winfo_children():
            w.destroy()
        self.scan_summary.configure(text="scanning…", text_color=C["muted"])
        self.update_idletasks()
        self.scan_results = scan_htdocs(root)
        flagged = sum(1 for r in self.scan_results
                      if r["user"] == "root" or r["pw_status"] == "blank")
        self.scan_summary.configure(
            text=f"{len(self.scan_results)} connection(s) · {flagged} need attention",
            text_color=C["text"])

        if not self.scan_results:
            ctk.CTkLabel(self.creds_list, text="No DB connections found.",
                         text_color=C["muted"], font=(MONO, 13)).pack(anchor="w", pady=8)
            return
        for i, r in enumerate(self.scan_results):
            risky = r["user"] == "root" or r["pw_status"] in ("blank", "variable")
            row = ctk.CTkFrame(self.creds_list, fg_color=C["row_b"] if i % 2 else C["row_a"],
                               corner_radius=6, border_width=1,
                               border_color=C["amber"] if risky else C["border"])
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=r["app"], width=150, anchor="w", font=(MONO, 13, "bold"),
                         text_color=C["text"]).pack(side="left", padx=6, pady=8)
            ctk.CTkLabel(row, text=r["kind"], width=130, anchor="w", font=(MONO, 12),
                         text_color=C["muted"]).pack(side="left", padx=6)
            ucol = C["red"] if r["user"] == "root" else C["text"]
            ctk.CTkLabel(row, text=r["user"] or "—", width=120, anchor="w", font=(MONO, 13),
                         text_color=ucol).pack(side="left", padx=6)
            ctk.CTkLabel(row, text=r["db"] or "—", width=140, anchor="w", font=(MONO, 12),
                         text_color=C["text"]).pack(side="left", padx=6)
            ps = r["pw_status"]
            pcol = {"set": C["green"], "blank": C["red"], "variable": C["muted"]}.get(ps, C["muted"])
            ctk.CTkLabel(row, text=ps, width=80, anchor="w", font=(MONO, 12),
                         text_color=pcol).pack(side="left", padx=6)
            if r["editable"]:
                ctk.CTkButton(row, text="Update", width=88, height=26, font=(MONO, 11, "bold"),
                              fg_color=C["card_hi"], hover_color=C["border"], text_color=C["cyan"],
                              command=lambda x=r: self._update_cred_dialog(x)).pack(side="left", padx=4)
            else:
                ctk.CTkButton(row, text="Open", width=88, height=26, font=(MONO, 11),
                              fg_color="transparent", border_width=1, border_color=C["border"],
                              text_color=C["muted"], hover_color=C["card_hi"],
                              command=lambda x=r: self._open_location(x)).pack(side="left", padx=4)

    def _open_location(self, r):
        folder = str(Path(r["file"]).parent)
        try:
            os.startfile(folder)  # Windows
        except Exception:
            messagebox.showinfo("FORGE/DB", f"File:\n{r['file']}")

    def _update_cred_dialog(self, r):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Update app credentials")
        dlg.geometry("560x430")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(80, dlg.lift)
        ctk.CTkLabel(dlg, text=f"Update — {r['app']}", font=(MONO, 17, "bold"),
                     text_color=C["cyan"]).pack(anchor="w", padx=22, pady=(20, 2))
        ctk.CTkLabel(dlg, text=r["file"], font=(MONO, 10), text_color=C["muted"],
                     wraplength=500, justify="left").pack(anchor="w", padx=22, pady=(0, 8))

        user_e = self._field(dlg, "DB user", r["user"] or "")
        pw_e = self._field(dlg, "DB password", "")
        prefill = getattr(self, "_last_created", None)
        if prefill:
            user_e.delete(0, "end"); user_e.insert(0, prefill[0])
            pw_e.insert(0, prefill[1])
        ctk.CTkLabel(dlg, text="Pre-filled from the last user you created (if any). The original file is\n"
                              "backed up to a .bak before any change.",
                     font=(MONO, 10), text_color=C["muted"], justify="left").pack(anchor="w", padx=22, pady=6)
        msg = ctk.CTkLabel(dlg, text="", font=(MONO, 11), text_color=C["muted"],
                           wraplength=510, justify="left"); msg.pack(anchor="w", padx=22, pady=8)

        def do_update():
            path = Path(r["file"])
            nu, npw = user_e.get().strip(), pw_e.get()
            if self.is_sim():
                self._record_fw_sim(f"Rewrite credentials in {path.name}",
                                    f"[file] back up {path} then set DB user='{nu}', new password (len {len(npw)})")
                msg.configure(text="🧪 Simulated — file NOT modified. Recorded in the Simulation Log.\n"
                                   "Turn off Simulation mode to apply for real.", text_color=C["amber"])
                return
            try:
                if r["kind"] == ".env":
                    b, a = rewrite_env_credentials(path, r.get("env_keys", {}), nu, npw)
                else:
                    b, a = rewrite_php_credentials(path, r["raw"], r["kind"], nu, npw)
                if b is None:
                    msg.configure(text="Nothing matched to rewrite — edit the file manually.", text_color=C["amber"])
                else:
                    msg.configure(text=f"✓ Updated (backup saved).\n\nbefore:\n{b}\n\nafter:\n{a}",
                                  text_color=C["green"])
                    self._do_scan()
            except Exception as e:
                msg.configure(text=f"✗ {e}", text_color=C["red"])

        ctk.CTkButton(dlg, text="Back up & update", height=40, font=(MONO, 14, "bold"),
                      fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                      command=do_update).pack(fill="x", padx=22, pady=(6, 16))

    def _bulk_rotate_dialog(self):
        editable = [r for r in self.scan_results if r.get("editable")]
        if not editable:
            messagebox.showinfo("FORGE/DB",
                                "No editable credentials found. Run a scan first — only PHP connect "
                                "calls and .env files with literal values can be rotated automatically.")
            return
        dlg = ctk.CTkToplevel(self)
        dlg.title("Bulk credential rotation")
        dlg.geometry("720x680")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self); dlg.after(80, dlg.lift)

        ctk.CTkLabel(dlg, text="Bulk credential rotation", font=(MONO, 18, "bold"),
                     text_color=C["gold"]).pack(anchor="w", padx=22, pady=(20, 2))
        ctk.CTkLabel(dlg, text="Select the files to update, then apply ONE database user + password to all of "
                              "them. Every file is backed up to a timestamped .bak before it is touched.\n\n"
                              "IMPORTANT: this only rewrites the files. The database account itself must already "
                              "exist with this password (create it on the Users tab first), otherwise the apps "
                              "will fail to connect after rotation.",
                     font=(MONO, 11), text_color=C["muted"], wraplength=660, justify="left").pack(anchor="w", padx=22)

        cred = ctk.CTkFrame(dlg, fg_color=C["card"], corner_radius=8)
        cred.pack(fill="x", padx=22, pady=10)
        user_e = self._field(cred, "DB user", "")
        pw_e = self._field(cred, "DB password", generate_password())
        prefill = getattr(self, "_last_created", None)
        if prefill:
            user_e.delete(0, "end"); user_e.insert(0, prefill[0])
            pw_e.delete(0, "end"); pw_e.insert(0, prefill[1])
            ctk.CTkLabel(cred, text="(pre-filled from the last scoped user you created)",
                         font=(MONO, 10), text_color=C["muted"]).pack(anchor="w", padx=18, pady=(2, 8))

        ctk.CTkLabel(dlg, text="Files to rotate", font=(MONO, 12, "bold"),
                     text_color=C["gold"]).pack(anchor="w", padx=22, pady=(6, 2))
        list_box = ctk.CTkScrollableFrame(dlg, fg_color=C["card"], height=240)
        list_box.pack(fill="both", expand=True, padx=22, pady=4)

        checks = []
        for r in editable:
            var = ctk.CTkCheckBox(
                list_box,
                text=f"{r['app']}  ·  {r['kind']}  ·  user={r['user'] or '—'}  ·  {Path(r['file']).name}",
                font=(MONO, 11))
            var.select()
            var.pack(anchor="w", padx=8, pady=3)
            checks.append((var, r))

        msg = ctk.CTkLabel(dlg, text="", font=(MONO, 11), text_color=C["muted"],
                           wraplength=660, justify="left")
        msg.pack(anchor="w", padx=22, pady=6)

        def do_rotate():
            chosen = [r for var, r in checks if var.get()]
            nu, npw = user_e.get().strip(), pw_e.get()
            if not chosen:
                msg.configure(text="Pick at least one file.", text_color=C["amber"]); return
            if not nu or not npw:
                msg.configure(text="Enter both a DB user and password.", text_color=C["amber"]); return
            if not self.confirm_risk(
                    "Rotate credentials in selected files",
                    f"Rewrite the DB user/password in {len(chosen)} file(s) to user '{nu}'.",
                    "Each file is backed up first, but if the matching database account does not "
                    "exist with this exact password, those apps will fail to connect until fixed.",
                    level="caution"):
                return
            if self.is_sim():
                for r in chosen:
                    p = Path(r["file"])
                    self._record_fw_sim(f"Rewrite credentials in {p.name}",
                                        f"[file] back up {p} then set DB user='{nu}', new password (len {len(npw)})")
                msg.configure(text=f"🧪 Simulated — {len(chosen)} file(s) NOT modified. "
                                   "Recorded in the Simulation Log.\nTurn off Simulation mode to apply for real.",
                              text_color=C["amber"])
                return
            results = []
            for r in chosen:
                path = Path(r["file"])
                try:
                    if r["kind"] == ".env":
                        b, a = rewrite_env_credentials(path, r.get("env_keys", {}), nu, npw)
                    else:
                        b, a = rewrite_php_credentials(path, r["raw"], r["kind"], nu, npw)
                    if b is None:
                        results.append((False, r["app"], path.name, "nothing matched"))
                    else:
                        results.append((True, r["app"], path.name, "updated + backed up"))
                except Exception as e:
                    results.append((False, r["app"], path.name, str(e)))
            ok = sum(1 for x in results if x[0])
            bad = len(results) - ok
            lines = [("✓ " if x[0] else "✗ ") + f"{x[1]} / {x[2]} — {x[3]}" for x in results]
            msg.configure(text=f"Rotated {ok} file(s), {bad} skipped/failed.\n\n" + "\n".join(lines),
                          text_color=C["green"] if bad == 0 else C["amber"])
            self._do_scan()

        ctk.CTkButton(dlg, text="Back up & rotate selected", height=42, font=(MONO, 14, "bold"),
                      fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                      command=do_rotate).pack(fill="x", padx=22, pady=(6, 16))

    # ======================================================================
    # PAGE: Network & Ports
    # ======================================================================
    def _page_network(self, p):
        self._header(p, "Network & Ports",
                     "Audit what's listening, and open/close ports on the Windows Firewall (host layer).")

        nbar = ctk.CTkFrame(p, fg_color="transparent")
        nbar.pack(fill="x", padx=28, pady=(2, 0))
        ctk.CTkButton(nbar, text="Scan listeners", width=140, height=38, font=(MONO, 14, "bold"),
                      fg_color=C["cyan"], text_color="#04222a", hover_color="#4ef0ff",
                      command=self._scan_listeners).pack(side="left")
        self.listen_summary = ctk.CTkLabel(nbar, text="", font=(MONO, 12), text_color=C["muted"])
        self.listen_summary.pack(side="left", padx=14)

        lhead = ctk.CTkFrame(p, fg_color=C["panel"], corner_radius=8)
        lhead.pack(fill="x", padx=24, pady=(10, 0))
        for txt, w in (("PROTO", 64), ("ADDRESS : PORT", 230), ("SCOPE", 130), ("PID", 70), ("PROCESS", 220)):
            ctk.CTkLabel(lhead, text=txt, width=w, anchor="w", font=(MONO, 11, "bold"),
                         text_color=C["gold"]).pack(side="left", padx=6, pady=8)
        self.listen_list = ctk.CTkScrollableFrame(p, fg_color=C["bg"], height=230)
        self.listen_list.pack(fill="x", padx=24, pady=(4, 6))

        fw = ctk.CTkFrame(p, fg_color=C["card"], corner_radius=10, border_width=1, border_color=C["border"])
        fw.pack(fill="x", padx=24, pady=(8, 4))
        top = ctk.CTkFrame(fw, fg_color="transparent"); top.pack(fill="x", padx=14, pady=(12, 2))
        ctk.CTkLabel(top, text="Windows Firewall", font=(MONO, 15, "bold"), text_color=C["text"]).pack(side="left")
        self.admin_lbl = ctk.CTkLabel(top, text="", font=(MONO, 12, "bold")); self.admin_lbl.pack(side="left", padx=12)
        self.elevate_btn = ctk.CTkButton(top, text="Run as Administrator", width=180, height=30, font=(MONO, 12, "bold"),
                                         fg_color=C["gold"], text_color="#241a00", hover_color="#ffd47a",
                                         command=self._elevate)
        ctk.CTkLabel(fw, text="Note: this is the host firewall. The nfoservers panel is the layer the internet "
                              "actually hits — keep your 3306/3389 blocks there too.",
                     font=(MONO, 10), text_color=C["muted"], justify="left", wraplength=900).pack(anchor="w", padx=14, pady=(2, 6))

        ctrl = ctk.CTkFrame(fw, fg_color="transparent"); ctrl.pack(fill="x", padx=14, pady=(2, 14))
        ctk.CTkLabel(ctrl, text="Port", font=(MONO, 13), text_color=C["muted"]).pack(side="left")
        self.fw_port = ctk.CTkEntry(ctrl, width=110, height=34, font=(MONO, 13), fg_color=C["bg"],
                                    border_color=C["border"], text_color=C["text"])
        self.fw_port.pack(side="left", padx=8)
        self.fw_proto = ctk.StringVar(value="TCP")
        ctk.CTkOptionMenu(ctrl, values=["TCP", "UDP"], variable=self.fw_proto, width=82,
                          font=(MONO, 13), fg_color=C["bg"], button_color=C["cyan_dim"]).pack(side="left")
        ctk.CTkButton(ctrl, text="Block inbound", width=130, height=34, font=(MONO, 13, "bold"),
                      fg_color="transparent", border_width=1, border_color=C["red"], text_color=C["red"],
                      hover_color="#3a1620", command=self._fw_block).pack(side="left", padx=8)
        ctk.CTkButton(ctrl, text="Allow inbound", width=130, height=34, font=(MONO, 13, "bold"),
                      fg_color="transparent", border_width=1, border_color=C["green"], text_color=C["green"],
                      hover_color="#16321f", command=self._fw_allow).pack(side="left")

        rbar = ctk.CTkFrame(p, fg_color="transparent"); rbar.pack(fill="x", padx=28, pady=(6, 0))
        ctk.CTkLabel(rbar, text="FORGE-DB firewall rules", font=(MONO, 13, "bold"), text_color=C["gold"]).pack(side="left")
        ctk.CTkButton(rbar, text="↻", width=36, height=28, font=(MONO, 13), fg_color=C["card_hi"],
                      hover_color=C["border"], text_color=C["text"], command=self._fw_refresh).pack(side="left", padx=8)
        self.fw_list = ctk.CTkScrollableFrame(p, fg_color=C["bg"], height=120)
        self.fw_list.pack(fill="x", padx=24, pady=(4, 14))

        self._refresh_admin()

    def _refresh_admin(self):
        if not IS_WINDOWS:
            self.admin_lbl.configure(text="(Windows only)", text_color=C["muted"])
            return
        if is_admin():
            self.admin_lbl.configure(text="● elevated", text_color=C["green"])
            self.elevate_btn.pack_forget()
        else:
            self.admin_lbl.configure(text="● not elevated — firewall changes need admin", text_color=C["amber"])
            self.elevate_btn.pack(side="left", padx=6)

    def _elevate(self):
        if relaunch_as_admin():
            self.destroy()
        else:
            messagebox.showinfo("FORGE/DB", "Couldn't relaunch automatically.\nClose the app and reopen it as Administrator.")

    def _scan_listeners(self):
        if not IS_WINDOWS:
            messagebox.showinfo("FORGE/DB", "Listener scan runs on Windows.")
            return
        for w in self.listen_list.winfo_children():
            w.destroy()
        self.listen_summary.configure(text="scanning…", text_color=C["muted"])
        self.update_idletasks()
        rows = list_listeners()
        exposed = sum(1 for r in rows if r["exposed"])
        self.listen_summary.configure(text=f"{len(rows)} listening · {exposed} on ALL interfaces",
                                      text_color=C["text"])
        if not rows:
            ctk.CTkLabel(self.listen_list, text="No listeners parsed.", text_color=C["muted"],
                         font=(MONO, 12)).pack(anchor="w", pady=6)
            return
        for i, r in enumerate(rows):
            row = ctk.CTkFrame(self.listen_list, fg_color=C["row_b"] if i % 2 else C["row_a"],
                               corner_radius=6, border_width=1,
                               border_color=C["amber"] if r["exposed"] else C["border"])
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=r["proto"], width=64, anchor="w", font=(MONO, 12),
                         text_color=C["muted"]).pack(side="left", padx=6, pady=7)
            ctk.CTkLabel(row, text=f'{r["host"]}:{r["port"]}', width=230, anchor="w", font=(MONO, 13),
                         text_color=C["text"]).pack(side="left", padx=6)
            scol = C["amber"] if r["exposed"] else (C["muted"] if r["scope"] == "local" else C["text"])
            stxt = "ALL (exposed)" if r["exposed"] else r["scope"]
            ctk.CTkLabel(row, text=stxt, width=130, anchor="w", font=(MONO, 12),
                         text_color=scol).pack(side="left", padx=6)
            ctk.CTkLabel(row, text=r["pid"], width=70, anchor="w", font=(MONO, 12),
                         text_color=C["muted"]).pack(side="left", padx=6)
            ctk.CTkLabel(row, text=r["process"], width=220, anchor="w", font=(MONO, 12),
                         text_color=C["text"]).pack(side="left", padx=6)

    def _ensure_admin(self):
        if is_admin():
            return True
        if messagebox.askyesno("FORGE/DB",
                               "Firewall changes require Administrator.\n\nRelaunch FORGE/DB as Administrator now?"):
            if relaunch_as_admin():
                self.destroy()
        return False

    def _valid_port(self, s):
        return bool(re.match(r"^\d{1,5}(-\d{1,5})?$", s))

    def _fw_block(self):
        port, proto = self.fw_port.get().strip(), self.fw_proto.get()
        if not self._valid_port(port):
            messagebox.showwarning("FORGE/DB", "Enter a port (e.g. 3306) or range (e.g. 8000-8100).")
            return
        if port in LOCKOUT_PORTS:
            if not messagebox.askyesno("⚠ RDP LOCKOUT RISK",
                    f"Port {port} is RDP. Blocking it on the host firewall can drop your current RDP "
                    "session and stop you reconnecting to the VPS.\n\nAre you sure?"):
                return
            if not messagebox.askyesno("⚠ Confirm again", "This could lock you out of the server.\n\nProceed with blocking RDP?"):
                return
        elif not messagebox.askyesno("FORGE/DB", f"Block inbound {proto} on port {port}?"):
            return
        if self.is_sim():
            cmd = fw_add_rule_cmd("block", proto, port)
            self._record_fw_sim(f"Block inbound {proto} port {port}", cmd)
            messagebox.showinfo("FORGE/DB — simulation",
                                f"Recorded (not applied):\n\n{cmd}\n\nOpen the Simulation Log to review.")
            return
        if not self._ensure_admin():
            return
        self._fw_result(*fw_add_rule("block", proto, port))

    def _fw_allow(self):
        port, proto = self.fw_port.get().strip(), self.fw_proto.get()
        if not self._valid_port(port):
            messagebox.showwarning("FORGE/DB", "Enter a port or range.")
            return
        if not messagebox.askyesno("FORGE/DB",
                f"Allow inbound {proto} on port {port}?\n\nThis opens the host firewall for that port — "
                "be sure you want it reachable."):
            return
        if self.is_sim():
            cmd = fw_add_rule_cmd("allow", proto, port)
            self._record_fw_sim(f"Allow inbound {proto} port {port}", cmd)
            messagebox.showinfo("FORGE/DB — simulation",
                                f"Recorded (not applied):\n\n{cmd}\n\nOpen the Simulation Log to review.")
            return
        if not self._ensure_admin():
            return
        self._fw_result(*fw_add_rule("allow", proto, port))

    def _fw_result(self, ok, msg, cmd):
        if ok:
            messagebox.showinfo("FORGE/DB", f"Rule applied.\n\nCommand:\n{cmd}")
        else:
            messagebox.showerror("FORGE/DB", f"Failed.\n\nCommand:\n{cmd}\n\n{msg}")
        self._fw_refresh()
        self._scan_listeners()

    def _fw_refresh(self):
        for w in self.fw_list.winfo_children():
            w.destroy()
        if not IS_WINDOWS:
            ctk.CTkLabel(self.fw_list, text="(Windows only)", text_color=C["muted"], font=(MONO, 12)).pack(anchor="w", pady=6)
            return
        rules = fw_list_forge_rules()
        if not rules:
            ctk.CTkLabel(self.fw_list, text="No FORGE-DB rules yet.", text_color=C["muted"], font=(MONO, 12)).pack(anchor="w", pady=6)
            return
        for i, r in enumerate(rules):
            row = ctk.CTkFrame(self.fw_list, fg_color=C["row_b"] if i % 2 else C["row_a"], corner_radius=6)
            row.pack(fill="x", pady=2)
            act = (r.get("action") or "").lower()
            ctk.CTkLabel(row, text=r.get("action", "?"), width=80, anchor="w", font=(MONO, 12, "bold"),
                         text_color=C["red"] if "block" in act else C["green"]).pack(side="left", padx=8, pady=6)
            ctk.CTkLabel(row, text=f'{r.get("proto","?")}  port {r.get("port","?")}  ({r.get("dir","?")})',
                         anchor="w", font=(MONO, 12), text_color=C["text"]).pack(side="left", padx=6)
            ctk.CTkButton(row, text="Remove", width=80, height=26, font=(MONO, 11),
                          fg_color="transparent", border_width=1, border_color=C["border"],
                          text_color=C["muted"], hover_color=C["card_hi"],
                          command=lambda n=r["name"]: self._fw_remove(n)).pack(side="right", padx=8)

    def _fw_remove(self, name):
        if not messagebox.askyesno("FORGE/DB", f"Remove this firewall rule?\n\n{name}"):
            return
        if self.is_sim():
            cmd = fw_delete_rule_cmd(name)
            self._record_fw_sim(f"Remove firewall rule {name}", cmd)
            messagebox.showinfo("FORGE/DB — simulation",
                                f"Recorded (not applied):\n\n{cmd}\n\nOpen the Simulation Log to review.")
            return
        if not self._ensure_admin():
            return
        self._fw_result(*fw_delete_rule(name))

    # ======================================================================
    # PAGE: Guide & Help
    # ======================================================================
    def _page_guide(self, p):
        self._header(p, "Guide & Help",
                     "Plain-language reference for every feature, the risk levels, and how to stay safe.")
        body = ctk.CTkScrollableFrame(p, fg_color=C["bg"])
        body.pack(fill="both", expand=True, padx=24, pady=(6, 12))

        def section(title, color, lines):
            card = ctk.CTkFrame(body, fg_color=C["card"], corner_radius=10,
                                border_width=1, border_color=C["border"])
            card.pack(fill="x", pady=6, padx=2)
            ctk.CTkLabel(card, text=title, font=(MONO, 15, "bold"),
                         text_color=color).pack(anchor="w", padx=16, pady=(12, 4))
            for lead, txt in lines:
                row = ctk.CTkFrame(card, fg_color="transparent")
                row.pack(fill="x", padx=16, pady=(0, 6))
                if lead:
                    ctk.CTkLabel(row, text=lead, font=(MONO, 12, "bold"), text_color=C["gold"],
                                 width=140, anchor="nw", justify="left").pack(side="left")
                ctk.CTkLabel(row, text=txt, font=(MONO, 12), text_color=C["text"],
                             justify="left", wraplength=720, anchor="w").pack(side="left", fill="x", expand=True)

        section("🧪 Simulation mode (dry-run)", C["amber"], [
            ("What it is", "A safety switch in the sidebar. When ON, FORGE/DB pretends to make changes but "
                           "applies nothing — every would-be SQL statement and firewall command is recorded."),
            ("Why use it", "Preview exactly what a fix, hardening pass, password rotation, or firewall rule "
                           "would do BEFORE you touch the live server. Your sites keep running untouched."),
            ("How", "Flip 'Simulation mode' on, perform the action as normal, then open 'View simulation log' "
                    "to read the captured statements. Turn it off to apply for real."),
        ])
        section("🔒 Risk levels", C["cyan"], [
            ("✓ SAFE", "Reversible in effect and won't cut off connectivity (e.g. removing an anonymous "
                       "login or the unused 'test' database)."),
            ("⚠ CAUTION", "Could break an app or a remote client if something still relies on it (e.g. locking "
                          "a '%' wildcard host to localhost). You are always warned first."),
            ("⛔ DANGER", "Permanent and not undoable (e.g. dropping a user or database). Requires a double "
                         "confirmation unless you are in simulation mode."),
        ])
        section("◇ Connection", C["text"], [
            ("Purpose", "Log in to MySQL/MariaDB on this machine. The password lives in memory only and is "
                        "never written to disk."),
            ("Tip", "Connect as root (or another admin) to use the audit and user-management features."),
        ])
        section("▲ Security Audit", C["text"], [
            ("Purpose", "Read-only scan of your accounts and defaults — anonymous users, '%' wildcard hosts, "
                        "blank passwords, over-privileged app accounts, the leftover 'test' DB."),
            ("Security score", "A 0–100 posture number (grade A–F). It only measures; it changes nothing."),
            ("Full hardening", "Applies a reviewed batch of fixes. SAFE items by default; CAUTION items only "
                               "with the aggressive toggle. Preview it in simulation mode first."),
        ])
        section("◈ Users", C["text"], [
            ("Purpose", "See every MySQL account with risky ones flagged. Create scoped, least-privilege app "
                        "users, change passwords, lock a host to localhost, or drop an account."),
            ("Keep sites up", "Prefer creating a new scoped user and updating the app's config over dropping "
                              "the account a live site still uses."),
        ])
        section("⚙ App Credentials", C["text"], [
            ("Purpose", "Scan C:\\xampp\\htdocs for the DB credentials your PHP/.env apps use, see who uses "
                        "what, and rotate passwords in place."),
            ("Safety", "Every file is backed up (.forgedbak) before it is rewritten, so a bad rotation is "
                       "easy to undo. The matching DB account must exist or the app will fail to connect."),
        ])
        section("⇄ Network & Ports", C["text"], [
            ("Purpose", "See what is listening on the machine and add Windows Firewall rules to block/allow "
                        "ports at the host layer."),
            ("Lockout guard", "Blocking RDP (3389) can drop your own session — FORGE/DB warns twice. The "
                              "host firewall is not the same as your provider's edge firewall; keep both tight."),
        ])
        section("Best practices", C["green"], [
            ("Run locally", "Use FORGE/DB on the VPS over RDP. Keep the .exe OUTSIDE C:\\xampp\\htdocs so "
                            "Apache never serves it."),
            ("Preview first", "When in doubt, simulate. Then export the audit report so you have a record."),
            ("Least privilege", "Give each app its own scoped, GRANT-less user limited to its own database."),
        ])

    # ======================================================================
    # PAGE: Settings
    # ======================================================================
    def _page_settings(self, p):
        self._header(p, "Settings", "Defaults and a quick local check.")
        card = ctk.CTkFrame(p, fg_color=C["card"], corner_radius=12, border_width=1, border_color=C["border"])
        card.pack(fill="x", padx=28, pady=10)

        self.ini_e = self._field(card, "my.ini path", self.cfg.get("myini", r"C:\xampp\mysql\bin\my.ini"))
        row = ctk.CTkFrame(card, fg_color="transparent"); row.pack(fill="x", padx=18, pady=14)
        ctk.CTkButton(row, text="Check bind-address", width=180, height=36, font=(MONO, 13),
                      fg_color=C["cyan_dim"], hover_color=C["cyan"], text_color=C["text"],
                      command=self._check_bind).pack(side="left")
        self.bind_lbl = ctk.CTkLabel(row, text="", font=(MONO, 13)); self.bind_lbl.pack(side="left", padx=14)

        gen_row = ctk.CTkFrame(card, fg_color="transparent"); gen_row.pack(fill="x", padx=18, pady=(0, 16))
        ctk.CTkButton(gen_row, text="Generate strong password", width=210, height=36, font=(MONO, 13),
                      fg_color="transparent", border_width=1, border_color=C["border"],
                      text_color=C["gold"], hover_color=C["card_hi"],
                      command=self._gen_pw).pack(side="left")
        self.gen_lbl = ctk.CTkLabel(gen_row, text="", font=(MONO, 13), text_color=C["green"])
        self.gen_lbl.pack(side="left", padx=14)

        ctk.CTkLabel(p, text="FORGE/DB · Digital-Synergy LLC · runs locally on the VPS only",
                     font=(MONO, 10), text_color=C["muted"]).pack(side="bottom", pady=14)

    def _check_bind(self):
        path = Path(self.ini_e.get().strip())
        self.cfg["myini"] = str(path); save_config(self.cfg)
        if not path.exists():
            self.bind_lbl.configure(text="my.ini not found.", text_color=C["red"]); return
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"^\s*bind-address\s*=\s*(\S+)", txt, re.IGNORECASE | re.MULTILINE)
            if m and m.group(1) in ("127.0.0.1", "localhost", "::1"):
                self.bind_lbl.configure(text=f"✓ bound to {m.group(1)} (local only)", text_color=C["green"])
            elif m:
                self.bind_lbl.configure(text=f"⚠ bind-address = {m.group(1)} — not loopback", text_color=C["amber"])
            else:
                self.bind_lbl.configure(text="⚠ no bind-address set — MySQL may listen on all interfaces",
                                        text_color=C["amber"])
        except Exception as e:
            self.bind_lbl.configure(text=f"error: {e}", text_color=C["red"])

    def _gen_pw(self):
        self.gen_lbl.configure(text=generate_password())


# ==============================================================================
# Startup dependency self-check
# ==============================================================================
def check_dependencies() -> list:
    """Return a list of (name, ok, hint) for the libraries this tool needs."""
    checks = []
    checks.append(("pymysql", PYMYSQL_OK,
                   "Required for all database features. Install with: pip install pymysql"))
    try:
        import customtkinter  # noqa: F401
        ctk_ok = True
    except Exception:
        ctk_ok = False
    checks.append(("customtkinter", ctk_ok,
                   "Required for the desktop UI. Install with: pip install customtkinter"))
    try:
        import PIL  # noqa: F401
        pil_ok = True
    except Exception:
        pil_ok = False
    checks.append(("Pillow", pil_ok,
                   "Optional — enables logo/header branding images. Install with: pip install Pillow"))
    return checks


# ==============================================================================
# CLI mode  (headless: audit / scan / export / harden)
# ==============================================================================
def _cli_password(args) -> str:
    """Resolve the MySQL password: --password, then FORGEDB_PASSWORD env, then prompt."""
    if args.password:
        return args.password
    env = os.environ.get("FORGEDB_PASSWORD")
    if env is not None:
        return env
    import getpass
    return getpass.getpass("MySQL password: ")


def run_cli(argv) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="forge_vps_security",
        description="FORGE/DB — headless database security audit / scan / hardening.")
    parser.add_argument("command", choices=["audit", "scan", "export", "harden", "doctor"],
                        help="audit: print findings · scan: htdocs creds · export: write JSON+CSV · "
                             "harden: apply safe remediations · doctor: dependency check")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="3306")
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default=None,
                        help="MySQL password (else FORGEDB_PASSWORD env, else interactive prompt).")
    parser.add_argument("--htdocs", default=r"C:\xampp\htdocs", help="Folder to scan for app credentials.")
    parser.add_argument("--out", default=None, help="Output path/prefix for export (default: reports/).")
    parser.add_argument("--aggressive", action="store_true",
                        help="With 'harden', also apply CAUTION actions (may break apps/remote clients).")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt for 'harden'.")
    args = parser.parse_args(argv)

    if args.command == "doctor":
        print("FORGE/DB dependency check:")
        all_ok = True
        for name, ok, hint in check_dependencies():
            print(f"  [{'OK ' if ok else 'MISS'}] {name}" + ("" if ok else f"  -> {hint}"))
            if not ok and name != "Pillow":
                all_ok = False
        return 0 if all_ok else 1

    if args.command == "scan":
        results = scan_htdocs(args.htdocs)
        flagged = [r for r in results if r["user"] == "root" or r["pw_status"] in ("blank", "variable")]
        print(f"{len(results)} connection(s) found · {len(flagged)} need attention\n")
        for r in results:
            mark = "!" if (r["user"] == "root" or r["pw_status"] in ("blank", "variable")) else " "
            print(f" [{mark}] {r['app']:<18} {r['kind']:<16} user={r['user'] or '-':<14} "
                  f"db={r['db'] or '-':<14} pw={r['pw_status']}")
        return 0

    if not PYMYSQL_OK:
        print("ERROR: PyMySQL is not installed. Run: pip install pymysql", file=sys.stderr)
        return 2

    db = DB()
    try:
        ver = db.connect(args.host, args.port, args.user, _cli_password(args))
    except Exception as e:
        print(f"ERROR: could not connect: {e}", file=sys.stderr)
        return 2
    print(f"Connected — {ver}\n")

    try:
        if args.command == "audit":
            findings = db.audit()
            for sev, title, detail, _ in findings:
                print(f"[{sev:<6}] {title}\n          {detail}")
            high = sum(1 for f in findings if f[0] == "HIGH")
            return 1 if high else 0

        if args.command == "export":
            findings = db.audit()
            users = db.users()
            scan_results = scan_htdocs(args.htdocs) if os.path.isdir(args.htdocs) else []
            report = build_report(db.info, findings, users, scan_results)
            if args.out:
                base = Path(args.out)
                jpath = base.with_suffix(".json")
                cpath = base.with_suffix(".csv")
            else:
                jpath, cpath = timestamped_report_paths()
            export_report_json(report, jpath)
            export_report_csv(report, cpath)
            print(f"Wrote:\n  {jpath}\n  {cpath}")
            return 0

        if args.command == "harden":
            plan = db.plan_hardening(aggressive=args.aggressive)
            if not plan:
                print("Nothing to harden — looks clean already.")
                return 0
            print(f"Planned actions ({'aggressive' if args.aggressive else 'safe-only'}):")
            for step in plan:
                print(f"  [{step['risk'].upper():<7}] {step['label']}")
            if not args.yes:
                ans = input("\nApply these actions? [y/N] ").strip().lower()
                if ans not in ("y", "yes"):
                    print("Aborted.")
                    return 0
            results, _ = db.run_hardening(aggressive=args.aggressive)
            for ok, label, msg in results:
                print(("  OK   " if ok else "  FAIL ") + label + ("" if ok else f" — {msg}"))
            return 0 if all(r[0] for r in results) else 1
    finally:
        db.close()
    return 0


def run_gui() -> int:
    # Surface a hard dependency problem before tkinter even loads.
    missing = [n for n, ok, _ in check_dependencies() if not ok and n in ("customtkinter",)]
    if missing:
        print("Missing required dependency: customtkinter\n"
              "Install with: pip install customtkinter", file=sys.stderr)
        return 2
    app = ForgeDB()
    # Non-fatal heads-up about optional/important libraries, shown once the window exists.
    problems = [(n, hint) for n, ok, hint in check_dependencies() if not ok]
    if problems:
        lines = "\n".join(f"• {n}: {hint}" for n, hint in problems)
        app.after(400, lambda: messagebox.showwarning(
            "FORGE/DB — dependency check",
            "Some libraries are missing. The app will run, but related features may be "
            f"limited:\n\n{lines}"))
    app.mainloop()
    return 0


if __name__ == "__main__":
    _CLI_COMMANDS = ("audit", "scan", "export", "harden", "doctor")
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("FORGE/DB — VPS database security console\n")
        print("Usage:")
        print("  forge_vps_security                 launch the graphical app")
        print("  forge_vps_security <command> ...   run headless (see commands below)\n")
        print("Commands: " + ", ".join(_CLI_COMMANDS))
        print("Run 'forge_vps_security <command> --help' for command options.")
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] in _CLI_COMMANDS:
        sys.exit(run_cli(sys.argv[1:]))
    sys.exit(run_gui())
