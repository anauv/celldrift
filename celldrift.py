#!/usr/bin/env python3
"""CellDrift: find battery cells that drift away from their neighbours.

A cell self-discharge logger for the Battery Emulator (github.com/dalathegreat/Battery-Emulator).

Logs every cell voltage of a battery pack at a fixed interval, so you can spot cells
that self-discharge faster than their neighbours. Optionally switches the emulator's
power on and off through Home Assistant around every measurement.

Each run:
  1. (optional) switch the power on through the Home Assistant REST API,
  2. wait until the emulator's cellmonitor reports all cells with stable values,
  3. store cell voltages and pack temperature in a small SQLite database,
  4. (optional) switch the power off again, also when the measurement failed.

A built-in web server (HTTPS when a certificate is present) shows graphs of selected
cells, modules and temperature, ranks cells that lose voltage faster than their module,
and has a settings page for everything: emulator address, cell/module layout,
interval, Home Assistant, password and clearing the data.

Only the Python standard library is used (Python 3.8+).

    python3 celldrift.py                  # uses ./config.json, created on first start
    python3 celldrift.py --once           # one measurement, then exit
"""

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULTS = {
    "pack_name": "Battery pack",
    "emulator_url": "http://192.168.1.100",   # Battery Emulator web interface
    "battery_index": 1,                       # 1 = first battery, 2 = second (double battery setups)
    "expected_cells": 0,                      # 0 = take whatever the emulator reports
    "cells_per_module": 12,                   # 0 = no module grouping
    "min_mv": 2000,                           # readings outside this range count as "not ready"
    "max_mv": 4500,
    "interval_minutes": 60,
    "align_to_interval": True,                # run at :00 instead of "60 minutes after start"
    "wait_timeout_s": 300,                    # give up when the emulator is not ready in time
    "settle_s": 30,                           # keep reading this long after the first complete reading
    "poll_s": 5,
    "ha_url": "",                             # e.g. https://192.168.1.10:8123 ; empty = no Home Assistant
    "ha_token_file": "ha_token.txt",          # or set the HA_TOKEN environment variable
    "ha_entity": "",                          # e.g. switch.battery_emulator ; empty = never switch
    "ha_verify_ssl": False,
    "power_off_after": True,
    "db_path": "celldrift.db",
    "http_host": "0.0.0.0",
    "http_port": 8100,
    "tls_cert": "tls/cert.pem",               # HTTPS is used when both files exist (see make_cert.sh)
    "tls_key": "tls/key.pem",
    "auth_enabled": False,                    # set from the settings page
    "password_hash": "",
}

# Battery Emulator status page: "Temperature min/max: 12.5 &deg;C / 14.0 &deg;C" (older builds: separate lines)
_NUM = r"(-?\d+(?:[.,]\d+)?)"
TEMP_PATTERNS = [
    re.compile(r"Temperature\s*min\s*/\s*max:\s*" + _NUM + r"[^/<]*/\s*" + _NUM, re.I),
    re.compile(r"Temperature\s*min:\s*" + _NUM + r"[\s\S]{0,200}?Temperature\s*max:\s*" + _NUM, re.I),
    re.compile(r"Temperature\s*max:\s*" + _NUM + r"[\s\S]{0,200}?Temperature\s*min:\s*" + _NUM, re.I),
]

_db_lock = threading.Lock()
_measure_lock = threading.Lock()
_wake = threading.Event()
STATE = {"next_run": None, "busy": False, "phase": "", "last_message": ""}


def log(msg):
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S}  {msg}", flush=True)


# ---------------------------------------------------------------- authentication

SESSION_COOKIE = "celldrift_session"
SESSION_TTL = 7 * 86400
_auth_lock = threading.Lock()
_sessions = {}            # token -> expiry (memory only: a restart logs everyone out)
_login_fails = {}         # ip -> [failure timestamps]


def hash_password(password, iterations=310000):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(check.hex(), digest)


def new_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _auth_lock:
        for t in [t for t, exp in _sessions.items() if exp < now]:
            del _sessions[t]
        _sessions[token] = now + SESSION_TTL
    return token


def session_valid(token):
    if not token:
        return False
    with _auth_lock:
        exp = _sessions.get(token)
        return bool(exp and exp > time.time())


def end_session(token):
    with _auth_lock:
        _sessions.pop(token, None)


def end_all_sessions():
    with _auth_lock:
        _sessions.clear()


def login_blocked(ip, limit=5, window=900):
    now = time.time()
    with _auth_lock:
        recent = [t for t in _login_fails.get(ip, []) if now - t < window]
        _login_fails[ip] = recent
        return len(recent) >= limit


def login_failed(ip):
    with _auth_lock:
        _login_fails.setdefault(ip, []).append(time.time())


def login_reset(ip):
    with _auth_lock:
        _login_fails.pop(ip, None)


def is_local_address(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------- config / db

def load_config(path):
    cfg = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    base = os.path.dirname(os.path.abspath(path))
    for key in ("db_path", "ha_token_file", "tls_cert", "tls_key"):
        if cfg[key] and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])
    cfg["_config_path"] = os.path.abspath(path)
    return cfg


def save_config(cfg, updates):
    """Merge `updates` into the JSON config file (other keys untouched) and into the running cfg."""
    path = cfg["_config_path"]
    stored = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            stored = json.load(f)
    stored.update(updates)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # holds the password hash
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(stored, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    cfg.update(updates)


def write_default_config(path):
    keys = ["pack_name", "emulator_url", "battery_index", "expected_cells", "cells_per_module", "min_mv",
            "max_mv", "interval_minutes", "ha_url", "ha_entity", "http_port"]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({k: DEFAULTS[k] for k in keys}, f, indent=2)
        f.write("\n")


def save_token(cfg, token):
    fd = os.open(cfg["ha_token_file"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token.strip() + "\n")
    try:
        os.chmod(cfg["ha_token_file"], 0o600)
    except OSError:
        pass


def _int(body, key, lo, hi, label):
    try:
        v = int(str(body.get(key, "")).strip())
    except ValueError:
        raise ValueError(f"{label} must be a whole number.")
    if not lo <= v <= hi:
        raise ValueError(f"{label} must be between {lo} and {hi}.")
    return v


def _url(value, label, allow_empty):
    url = str(value or "").strip().rstrip("/")
    if not url and allow_empty:
        return ""
    if url and not re.match(r"^https?://", url):
        url = "http://" + url if label == "Battery Emulator address" else "https://" + url
    if not re.match(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$", url):
        raise ValueError(f"{label} should look like http://192.168.1.100 (optionally with :port).")
    return url


def validate_settings(body):
    """Return (updates, token or None) from a settings form post; raises ValueError with a message."""
    u = {}
    name = str(body.get("pack_name", "")).strip()
    if not 1 <= len(name) <= 60:
        raise ValueError("Pack name must be 1 to 60 characters.")
    u["pack_name"] = name
    u["emulator_url"] = _url(body.get("emulator_url"), "Battery Emulator address", False)
    u["battery_index"] = _int(body, "battery_index", 1, 4, "Battery number")
    u["expected_cells"] = _int(body, "expected_cells", 0, 1000, "Number of cells")
    u["cells_per_module"] = _int(body, "cells_per_module", 0, 1000, "Cells per module")
    u["min_mv"] = _int(body, "min_mv", 500, 5000, "Lowest valid cell voltage")
    u["max_mv"] = _int(body, "max_mv", 500, 5000, "Highest valid cell voltage")
    if u["min_mv"] >= u["max_mv"]:
        raise ValueError("Lowest valid cell voltage must be below the highest.")
    u["interval_minutes"] = _int(body, "interval_minutes", 1, 1440, "Interval")
    u["ha_url"] = _url(body.get("ha_url"), "Home Assistant address", True)
    entity = str(body.get("ha_entity", "")).strip()
    if entity and not re.match(r"^[a-z_]+\.[a-z0-9_]+$", entity):
        raise ValueError("Entity should look like switch.battery_emulator (or empty to never switch).")
    if entity and not u["ha_url"]:
        raise ValueError("Fill in the Home Assistant address to switch an entity.")
    u["ha_entity"] = entity
    token = str(body.get("ha_token", "")).strip()
    if token and (len(token) < 20 or re.search(r"\s", token)):
        raise ValueError("That does not look like a Home Assistant access token.")
    return u, token or None


def open_db(path):
    con = sqlite3.connect(path, check_same_thread=False)
    con.execute("""CREATE TABLE IF NOT EXISTS measurements (
        id INTEGER PRIMARY KEY,
        ts REAL NOT NULL,
        cells TEXT NOT NULL,
        balancing INTEGER,
        temp_min REAL,
        temp_max REAL,
        raw TEXT,
        source TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY,
        ts REAL NOT NULL,
        ok INTEGER NOT NULL,
        message TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_meas_ts ON measurements(ts)")
    con.commit()
    return con


def db_exec(con, sql, args=()):
    with _db_lock:
        cur = con.execute(sql, args)
        con.commit()
        return cur


def db_query(con, sql, args=()):
    with _db_lock:
        return con.execute(sql, args).fetchall()


# ---------------------------------------------------------------- http helpers

def _ssl_ctx(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get_text(url, headers=None, verify=True, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    ctx = _ssl_ctx(verify) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read().decode("utf-8", "replace")


def http_json(url, method="GET", body=None, headers=None, verify=True, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    ctx = _ssl_ctx(verify) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        txt = r.read().decode("utf-8", "replace")
        return json.loads(txt) if txt.strip() else None


def ha_token(cfg):
    tok = os.environ.get("HA_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(cfg["ha_token_file"], encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def ha_switch(cfg, on):
    token = ha_token(cfg)
    if not token:
        raise RuntimeError("no Home Assistant access token set")
    entity = cfg["ha_entity"]
    domain = entity.split(".", 1)[0]
    url = f"{cfg['ha_url']}/api/services/{domain}/{'turn_on' if on else 'turn_off'}"
    http_json(url, "POST", {"entity_id": entity}, {"Authorization": f"Bearer {token}"}, verify=cfg["ha_verify_ssl"])


def ha_state(cfg, entity):
    url = f"{cfg['ha_url']}/api/states/{entity}"
    st = http_json(url, headers={"Authorization": f"Bearer {ha_token(cfg)}"}, verify=cfg["ha_verify_ssl"])
    return (st or {}).get("state")


def cellmonitor_url(cfg):
    return f"{cfg['emulator_url']}/cellmonitor?battery={cfg['battery_index']}&data=1"


def fetch_cells(cfg):
    """Raw cellmonitor reading: (cells, balancing_count, raw) or raise."""
    data = http_json(cellmonitor_url(cfg), timeout=10)
    cells = data.get("d") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        raise ValueError("no cell data in the cellmonitor response")
    balancing = sum(1 for b in data.get("b", []) if b)
    return cells, balancing, data


def read_cells(cfg):
    """Return (cells, balancing_count, raw) when the reading is complete, else None."""
    cells, balancing, data = fetch_cells(cfg)
    want = cfg["expected_cells"] or (data.get("n") if isinstance(data.get("n"), int) and data.get("n") > 0 else len(cells))
    if not cells or len(cells) != want:
        return None
    if not all(isinstance(v, (int, float)) and cfg["min_mv"] <= v <= cfg["max_mv"] for v in cells):
        return None
    return [int(v) for v in cells], balancing, data


def _num(s):
    return float(s.replace(",", "."))


def read_temperatures(cfg):
    """Best effort: (temp_min, temp_max) in degrees C from the emulator status page."""
    for path in ("/", "/live"):
        try:
            html = http_get_text(cfg["emulator_url"] + path, timeout=10)
        except Exception:
            continue
        for pat in TEMP_PATTERNS:
            m = pat.search(html)
            if m:
                a, b = _num(m.group(1)), _num(m.group(2))
                return min(a, b), max(a, b)
    return None, None


# ---------------------------------------------------------------- measurement

def switching(cfg):
    return bool(cfg["ha_entity"] and cfg["ha_url"])


def measure_once(cfg, con, source="schedule"):
    if not _measure_lock.acquire(blocking=False):
        return False, "a measurement is already running"
    STATE["busy"] = True
    switched_on = False
    ok, message = False, ""
    try:
        if switching(cfg):
            STATE["phase"] = "switching power on"
            ha_switch(cfg, True)
            switched_on = True
            log(f"{cfg['ha_entity']} switched on ({source})")
        STATE["phase"] = "waiting for all cells"
        deadline = time.time() + cfg["wait_timeout_s"]
        first_ok, result = None, None
        while time.time() < deadline:
            try:
                reading = read_cells(cfg)
            except (urllib.error.URLError, OSError, ValueError):
                reading = None
            if reading:
                if first_ok is None:
                    first_ok = time.time()
                    STATE["phase"] = "settling"
                    log("cellmonitor complete, letting values settle")
                result = reading
                if time.time() - first_ok >= cfg["settle_s"]:
                    break
            time.sleep(cfg["poll_s"])
        if result is None or first_ok is None or time.time() - first_ok < cfg["settle_s"]:
            raise TimeoutError(f"cellmonitor not complete within {cfg['wait_timeout_s']} s")
        cells, balancing, raw = result
        STATE["phase"] = "reading temperature"
        tmin, tmax = read_temperatures(cfg)
        db_exec(con, "INSERT INTO measurements(ts, cells, balancing, temp_min, temp_max, raw, source)"
                     " VALUES (?,?,?,?,?,?,?)",
                (time.time(), json.dumps(cells), balancing, tmin, tmax, json.dumps(raw), source))
        ok = True
        message = (f"saved ({source}): {len(cells)} cells, min {min(cells)} / max {max(cells)} mV, "
                   f"delta {max(cells) - min(cells)} mV")
        message += f", pack {tmin:g}–{tmax:g} °C" if tmin is not None else ", pack temperature not found"
        if balancing:
            message += f", NOTE: {balancing} cells balancing"
        log(message)
    except Exception as exc:  # keep the scheduler alive whatever happens
        message = f"failed ({source}): {exc}"
        log(message)
    finally:
        if switched_on and cfg["power_off_after"]:
            STATE["phase"] = "switching power off"
            for attempt in range(3):
                try:
                    ha_switch(cfg, False)
                    log(f"{cfg['ha_entity']} switched off")
                    break
                except Exception as exc:
                    log(f"switching off failed (attempt {attempt + 1}): {exc}")
                    time.sleep(5)
            else:
                message += " | SWITCHING OFF FAILED"
                ok = False
        db_exec(con, "INSERT INTO runs(ts, ok, message) VALUES (?,?,?)", (time.time(), int(ok), message))
        STATE.update(last_message=message, busy=False, phase="")
        _measure_lock.release()
    return ok, message


def next_run_time(cfg, now):
    step = cfg["interval_minutes"] * 60
    if cfg["align_to_interval"]:
        return (int(now // step) + 1) * step
    return now + step


def scheduler(cfg, con, run_now):
    if run_now:
        measure_once(cfg, con, "start")
    while True:
        nxt = next_run_time(cfg, time.time())
        STATE["next_run"] = nxt
        log(f"next measurement: {dt.datetime.fromtimestamp(nxt):%Y-%m-%d %H:%M}")
        action = "schedule"
        while time.time() < nxt:
            if _wake.wait(timeout=min(30, max(0.5, nxt - time.time()))):
                _wake.clear()
                action = "reschedule" if STATE.pop("reschedule", False) else "manual"
                break
        if action == "reschedule":
            continue
        measure_once(cfg, con, action)


def clear_data(cfg, con):
    """Back up the database next to it, then delete all measurements and runs."""
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = os.path.splitext(cfg["db_path"])[0] + f"-backup-{stamp}.db"
    with _db_lock:
        dst = sqlite3.connect(backup)
        con.backup(dst)
        dst.close()
        n_meas = con.execute("SELECT COUNT(*) FROM measurements").fetchone()[0]
        con.execute("DELETE FROM measurements")
        con.execute("DELETE FROM runs")
        con.commit()
        con.execute("VACUUM")
    log(f"data cleared: {n_meas} measurements removed, backup in {backup}")
    return n_meas, backup


def export_csv(con):
    rows = db_query(con, "SELECT ts, cells, balancing, temp_min, temp_max FROM measurements ORDER BY ts")
    n = max((len(json.loads(r[1])) for r in rows), default=0)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "balancing", "temp_min", "temp_max"] + [f"cell_{i}" for i in range(1, n + 1)])
    for ts, cells, bal, tmin, tmax in rows:
        w.writerow([f"{dt.datetime.fromtimestamp(ts):%Y-%m-%d %H:%M:%S}"]
                   + ["" if v is None else v for v in (bal, tmin, tmax)] + json.loads(cells))
    return buf.getvalue()


# ---------------------------------------------------------------- web server

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                               "form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def public_config(cfg):
    return {"pack_name": cfg["pack_name"], "cells_per_module": cfg["cells_per_module"]}


def make_handler(cfg, con):
    class Handler(BaseHTTPRequestHandler):
        timeout = 30                      # drop clients that stall (slowloris)
        server_version = "celldrift"
        sys_version = ""

        def log_message(self, *args):
            pass

        def send(self, code, body, ctype, extra=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def reply(self, code, **payload):
            self.send(code, json.dumps(payload), "application/json")

        def body_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 65536:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except ValueError:
                return {}

        # -- access control
        def client_ip(self):
            return self.client_address[0]

        def is_lan(self):
            return is_local_address(self.client_ip())

        def session_token(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == SESSION_COOKIE:
                    return value
            return ""

        def logged_in(self):
            return session_valid(self.session_token())

        def can_view(self):
            return not cfg["auth_enabled"] or self.logged_in()

        def can_control(self):
            return self.logged_in() if cfg["auth_enabled"] else self.is_lan()

        def cookie(self, token, max_age):
            secure = "; Secure" if cfg.get("_https") else ""
            return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

        def deny(self, api):
            if cfg["auth_enabled"] and not self.logged_in():
                if api:
                    self.reply(401, message="Log in first.")
                else:
                    self.send(303, "", "text/plain", {"Location": "login"})
            elif api:
                self.reply(403, message="Control is only possible from the local network, or turn on a password.")
            else:
                self.send(403, FORBIDDEN_PAGE, "text/html; charset=utf-8")

        def same_origin(self):
            """CSRF guard: JSON body only, and a browser Origin header must match our own host."""
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return False
            origin = self.headers.get("Origin")
            if origin:
                return re.sub(r"^https?://", "", origin).rstrip("/") == (self.headers.get("Host") or "")
            return True

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            api = path.startswith("/api/") or path == "/export.csv"
            if path == "/login":
                self.send(200, LOGIN_PAGE, "text/html; charset=utf-8")
                return
            if not self.can_view():
                self.deny(api)
                return
            if path in ("/", "/index.html"):
                self.send(200, PAGE, "text/html; charset=utf-8")
            elif path in ("/settings", "/api/config") and not self.can_control():
                self.deny(api)
            elif path == "/settings":
                self.send(200, SETTINGS_PAGE, "text/html; charset=utf-8")
            elif path == "/api/config":
                n_meas = db_query(con, "SELECT COUNT(*) FROM measurements")[0][0]
                n_runs = db_query(con, "SELECT COUNT(*) FROM runs")[0][0]
                keys = ["pack_name", "emulator_url", "battery_index", "expected_cells", "cells_per_module",
                        "min_mv", "max_mv", "interval_minutes", "ha_url", "ha_entity"]
                out = {k: cfg[k] for k in keys}
                out.update(token_set=bool(ha_token(cfg)), auth_enabled=bool(cfg["auth_enabled"]),
                           password_set=bool(cfg["password_hash"]), https=bool(cfg.get("_https")),
                           lan=self.is_lan(), measurements=n_meas, runs=n_runs)
                self.send(200, json.dumps(out), "application/json")
            elif path == "/api/data":
                rows = db_query(con, "SELECT ts, cells, balancing, temp_min, temp_max FROM measurements ORDER BY ts")
                out = dict(public_config(cfg),
                           rows=[{"t": ts, "d": json.loads(c), "b": b, "tmin": t1, "tmax": t2}
                                 for ts, c, b, t1, t2 in rows])
                self.send(200, json.dumps(out), "application/json")
            elif path == "/api/status":
                runs = db_query(con, "SELECT ts, ok, message FROM runs ORDER BY ts DESC LIMIT 15")
                out = dict(public_config(cfg), next_run=STATE["next_run"], busy=STATE["busy"], phase=STATE["phase"],
                           entity=cfg["ha_entity"] if switching(cfg) else "", interval_minutes=cfg["interval_minutes"],
                           can_control=self.can_control(), auth_enabled=bool(cfg["auth_enabled"]),
                           runs=[{"t": t, "ok": bool(o), "message": m} for t, o, m in runs])
                self.send(200, json.dumps(out), "application/json")
            elif path == "/export.csv":
                self.send(200, export_csv(con), "text/csv; charset=utf-8",
                          {"Content-Disposition": "attachment; filename=battery-cell-log.csv"})
            else:
                self.send(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if not self.same_origin():
                self.reply(403, message="Request refused.")
                return
            if path == "/api/login":
                ip = self.client_ip()
                if login_blocked(ip):
                    self.reply(429, message="Too many failed attempts. Try again in 15 minutes.")
                    return
                pw = str(self.body_json().get("password", ""))
                if cfg["password_hash"] and verify_password(pw, cfg["password_hash"]):
                    login_reset(ip)
                    log(f"logged in from {ip}")
                    self.send(200, json.dumps({"message": "Logged in."}), "application/json",
                              {"Set-Cookie": self.cookie(new_session(), SESSION_TTL)})
                else:
                    login_failed(ip)
                    log(f"failed login from {ip}")
                    time.sleep(1)
                    self.reply(401, message="Wrong password.")
                return
            if path == "/api/logout":
                end_session(self.session_token())
                self.send(200, json.dumps({"message": "Logged out."}), "application/json",
                          {"Set-Cookie": self.cookie("", 0)})
                return
            if not self.can_control():
                self.deny(True)
                return
            if path == "/api/measure":
                if STATE["busy"]:
                    self.reply(409, message="A measurement is already running.")
                else:
                    STATE["busy"] = True
                    STATE["phase"] = "started"
                    _wake.set()
                    self.reply(202, message="Measurement started.")
            elif path == "/api/config":
                self.save_settings(self.body_json())
            elif path == "/api/emulator-test":
                self.test_emulator(self.body_json())
            elif path == "/api/ha-test":
                self.test_ha()
            elif path == "/api/password":
                self.change_password(self.body_json())
            elif path == "/api/clear":
                if self.body_json().get("confirm") != "CLEAR":
                    self.reply(400, message="Type CLEAR to confirm.")
                elif STATE["busy"]:
                    self.reply(409, message="A measurement is running; try again in a moment.")
                else:
                    try:
                        n, backup = clear_data(cfg, con)
                        self.reply(200, message=f"{n} measurements removed. Backup: {os.path.basename(backup)}")
                    except (OSError, sqlite3.Error) as exc:
                        self.reply(500, message=f"clearing failed: {exc}")
            else:
                self.send(404, "not found", "text/plain; charset=utf-8")

        def save_settings(self, body):
            try:
                updates, token = validate_settings(body)
            except ValueError as exc:
                self.reply(400, message=str(exc))
                return
            if updates["ha_url"] and updates["ha_url"] != cfg["ha_url"] and ha_token(cfg) and not token:
                # never send a stored token to a new address without it being entered again
                self.reply(400, message="With a new Home Assistant address, enter the access token again.")
                return
            old = {k: cfg[k] for k in ("interval_minutes", "expected_cells", "cells_per_module")}
            try:
                save_config(cfg, updates)
                if token:
                    save_token(cfg, token)
            except OSError as exc:
                self.reply(500, message=f"saving failed: {exc}")
                return
            log(f"settings changed from {self.client_ip()}" + (" (new token)" if token else ""))
            if updates["interval_minutes"] != old["interval_minutes"] and not STATE["busy"]:
                STATE["reschedule"] = True
                _wake.set()
            msg = "Settings saved."
            has_data = db_query(con, "SELECT COUNT(*) FROM measurements")[0][0] > 0
            if has_data and (updates["expected_cells"] != old["expected_cells"]
                             or updates["cells_per_module"] != old["cells_per_module"]):
                msg += " The cell layout changed: clear the data if it belongs to a different pack."
            self.reply(200, message=msg)

        def test_emulator(self, body):
            try:
                url = _url(body.get("emulator_url") or cfg["emulator_url"], "Battery Emulator address", False)
                index = int(body.get("battery_index") or cfg["battery_index"])
            except (ValueError, TypeError) as exc:
                self.reply(200, ok=False, message=str(exc))
                return
            probe = dict(cfg, emulator_url=url, battery_index=index)
            try:
                cells, balancing, _ = fetch_cells(probe)
            except urllib.error.HTTPError as exc:
                self.reply(200, ok=False, message=f"Emulator answered HTTP {exc.code}. Is this a Battery Emulator?")
                return
            except Exception as exc:
                self.reply(200, ok=False, message=f"Emulator not reachable: {exc}")
                return
            valid = [v for v in cells if isinstance(v, (int, float)) and v > 0]
            if not valid:
                self.reply(200, ok=False, message="Connected, but no cell voltages yet (emulator still starting?).")
                return
            tmin, tmax = read_temperatures(probe)
            temp = f", pack {tmin:g}–{tmax:g} °C" if tmin is not None else ", pack temperature not found"
            self.reply(200, ok=True, cells=len(cells),
                       message=f"Connected: {len(cells)} cells, {min(valid)}–{max(valid)} mV, "
                               f"{balancing} balancing{temp}.")

        def test_ha(self):
            if not switching(cfg):
                self.reply(200, ok=False, message="No Home Assistant address or entity set.")
            elif not ha_token(cfg):
                self.reply(200, ok=False, message="No access token set yet.")
            else:
                try:
                    state = ha_state(cfg, cfg["ha_entity"])
                    self.reply(200, ok=True, message=f"Connected. {cfg['ha_entity']} is now: {state}")
                except urllib.error.HTTPError as exc:
                    hint = {401: "token invalid", 404: "entity does not exist"}.get(exc.code, f"HTTP {exc.code}")
                    self.reply(200, ok=False, message=f"Home Assistant refused: {hint}.")
                except Exception as exc:
                    self.reply(200, ok=False, message=f"Home Assistant not reachable: {exc}")

        def change_password(self, body):
            ip = self.client_ip()
            enabled = bool(body.get("enabled"))
            current = str(body.get("current", ""))
            new = str(body.get("new", ""))
            if cfg["password_hash"]:
                if login_blocked(ip):
                    self.reply(429, message="Too many failed attempts. Try again in 15 minutes.")
                    return
                if not verify_password(current, cfg["password_hash"]):
                    login_failed(ip)
                    self.reply(403, message="The current password is wrong.")
                    return
            new_hash = hash_password(new) if new else cfg["password_hash"]
            if enabled and not new_hash:
                self.reply(400, message="Set a password first.")
                return
            try:
                save_config(cfg, {"auth_enabled": enabled, "password_hash": new_hash})
            except OSError as exc:
                self.reply(500, message=f"saving failed: {exc}")
                return
            end_all_sessions()
            log(f"access changed from {ip}: password {'on' if enabled else 'off'}" + (", new password" if new else ""))
            extra = {"Set-Cookie": self.cookie(new_session(), SESSION_TTL)} if enabled else None
            msg = ("Password is on." if enabled else
                   "Password is off: anyone can view, control only from the local network.")
            self.send(200, json.dumps({"message": msg}), "application/json", extra)

    return Handler


class TLSServer(ThreadingHTTPServer):
    """HTTPS server: TLS handshake in the worker thread, plain http:// on the same port gets a 301 to https://."""
    daemon_threads = True

    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler)
        self.ctx = ctx

    def finish_request(self, request, client_address):
        request.settimeout(30)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if first and first[0] != 0x16:
            self.redirect_plain_http(request)
            return
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    @staticmethod
    def redirect_plain_http(sock):
        try:
            head = sock.recv(4096).decode("latin-1", "replace")
        except OSError:
            return
        lines = head.split("\r\n")
        parts = lines[0].split(" ") if lines else []
        path = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else "/"
        host = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
        if not re.match(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$", host) or not re.match(r"^/[\x21-\x7e]*$", path):
            body = b"Use https:// instead of http://\n"
            resp = (b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                    b"Connection: close\r\n\r\n" % len(body)) + body
        else:
            resp = (f"HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{path}\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").encode("latin-1")
        try:
            sock.sendall(resp)
        except OSError:
            pass


# ---------------------------------------------------------------- pages

STYLE_BASE = r"""
:root{--bg:#eef1f3;--panel:#fff;--ink:#17212b;--muted:#5b6874;--line:#d3dae0;--accent:#0d6f73;--ok:#2f7d4f;--warn:#b26b00;--bad:#c0262d;--badbg:#f8dcdd;--warnbg:#fbecd2;--chip:#e4ecee}
@media (prefers-color-scheme:dark){:root{--bg:#11171c;--panel:#182129;--ink:#e4eaee;--muted:#93a1ac;--line:#2c3842;--accent:#4fb8ba;--ok:#5cbf83;--warn:#e5a23b;--bad:#f0656b;--badbg:#42191c;--warnbg:#3a2c14;--chip:#21313a;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
h1{margin:0;font-size:26px}h2{margin:0;font-size:18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;display:grid;gap:12px;min-width:0}
.muted{color:var(--muted)}
a{color:var(--accent)}
"""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>CellDrift</title>
<style>""" + STYLE_BASE + r"""
.wrap{max-width:1200px;margin:0 auto;padding:18px 16px 40px;display:grid;gap:16px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
.row{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;justify-content:space-between}
.top{flex-wrap:nowrap;align-items:flex-start}.titleblock{flex:1 1 auto;min-width:0}
label{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px}
select,button{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 10px}
button{cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--panel);font-weight:600;padding:9px 16px}
button:disabled{opacity:.55;cursor:default}
.measure{display:flex;gap:12px;align-items:center;flex-wrap:wrap;justify-content:flex-end;flex:0 0 auto}
#phase{font-size:13px}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}
.stat{border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:0}
.stat .k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.stat .v{font:600 18px ui-monospace,Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.warnline{color:var(--warn);font-weight:600;grid-column:1/-1}
.chartbox{position:relative}
canvas{width:100%;display:block;touch-action:pan-y}
#c-cells{height:clamp(260px,52vh,440px)}#c-mods{height:clamp(220px,38vh,300px)}#c-temp{height:clamp(180px,30vh,240px)}
.tip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font-size:12px;white-space:nowrap;display:none;z-index:2}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:12px;color:var(--muted)}
.legend span::before{content:"";display:inline-block;width:14px;height:3px;margin-right:5px;vertical-align:middle;background:var(--c)}
details.picker{border:1px solid var(--line);border-radius:8px;padding:8px 12px}
details.picker summary{cursor:pointer;font-weight:600;padding:4px 0}
.quick{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.quick button{padding:4px 10px;font-size:13px}
.mods{display:grid;gap:6px;max-width:680px}
.mod{display:grid;grid-template-columns:72px 1fr;gap:4px;align-items:start}
.mod .mname{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px;padding-top:2px}
.mod .mname i{display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--c);flex:none}
.chips{display:grid;grid-template-columns:repeat(var(--cols),minmax(0,1fr));gap:4px}
.chipcell{font:12px ui-monospace,Consolas,monospace;padding:4px 0;width:100%;min-width:0;text-align:center;border-radius:5px;border:1px solid var(--line);background:var(--chip);color:var(--muted)}
.chipcell.on{background:var(--c);border-color:var(--c);color:#fff;font-weight:700}
.chipcell.flag{box-shadow:0 0 0 2px var(--bad) inset}
.tbl{overflow-x:auto;max-height:520px;overflow-y:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:5px 9px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
th{position:sticky;top:0;background:var(--panel);color:var(--muted);font-weight:600}
th:first-child,td:first-child{text-align:left}
td.num{font-family:ui-monospace,Consolas,monospace}
tr.b td{background:var(--badbg)}tr.w td{background:var(--warnbg)}
tbody tr{cursor:pointer}tr.sel td:first-child{box-shadow:inset 4px 0 0 var(--accent)}
.pill{font-size:11px;font-weight:700;border:1px solid currentColor;border-radius:999px;padding:1px 8px}
.pill.n{color:var(--ok)}.pill.w{color:var(--warn)}.pill.b{color:var(--bad)}.pill.x{color:var(--muted)}
.runs{display:grid;gap:4px;font-size:13px}.runs .err{color:var(--bad)}
@media (pointer:coarse){.chipcell{padding:9px 0;font-size:13px}.mod .mname button{padding:6px 10px!important}button,select{min-height:38px}.mods{max-width:none}}
@media (max-width:900px){.wrap{gap:12px;padding-top:12px}.panel{padding:12px}.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.stat .v{font-size:16px}}
@media (max-width:560px){
  h1{font-size:22px}.top{flex-wrap:wrap}
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
  .row>.row{width:100%;justify-content:stretch}
  .row>.row label{flex:1 1 100%;justify-content:space-between}
  .row>.row select{flex:1;max-width:70%}
  .measure{width:100%;justify-content:space-between}
  .mod{grid-template-columns:1fr;margin-bottom:4px}
  .chipcell{font-size:11px;padding:8px 0}
  table{font-size:12px}th,td{padding:5px 6px}
}
</style></head><body>
<div class="wrap">
  <div class="row top">
    <div class="titleblock"><h1 id="title">CellDrift</h1><div class="muted" id="sub">Loading…</div></div>
    <div class="measure"><span id="phase" class="muted"></span><a href="settings" id="setlink" hidden>Settings</a><a href="#" id="logout" hidden>Log out</a><button id="now" class="primary" hidden>Measure now</button></div>
  </div>
  <section class="panel"><div class="stats" id="stats"></div></section>

  <section class="panel">
    <div class="row">
      <h2>Cell voltages</h2>
      <div class="row" style="justify-content:flex-end">
        <label>View <select id="mode"><option value="abs" selected>Absolute (mV)</option><option value="delta">Change since baseline (mV)</option></select></label>
        <label>Baseline <select id="base"></select></label>
      </div>
    </div>
    <details class="picker" id="picker">
      <summary>Choose cells <span class="muted" id="selcount"></span></summary>
      <div class="quick">
        <button data-q="all">All cells</button><button data-q="none">None</button>
        <button data-q="flag">Only deviating</button><button data-q="low5">5 fastest dropping</button>
      </div>
      <div class="mods" id="mods"></div>
    </details>
    <div class="chartbox"><canvas id="c-cells"></canvas><div class="tip"></div></div>
    <div class="muted" style="font-size:12px">Colour = module. Deviating cells are drawn thick. Tap a cell number or a ranking row to show or hide it.</div>
  </section>

  <section class="panel" id="modpanel">
    <div class="row"><h2>Modules</h2><span class="muted" style="font-size:13px" id="modinfo"></span></div>
    <div class="chartbox"><canvas id="c-mods"></canvas><div class="tip"></div></div>
    <div class="legend" id="legend-mods"></div>
  </section>

  <section class="panel">
    <div class="row"><h2>Temperature</h2><span class="muted" style="font-size:13px">°C · pack min/max from the Battery Emulator</span></div>
    <div class="chartbox"><canvas id="c-temp"></canvas><div class="tip"></div></div>
    <div class="legend" id="legend-temp"></div>
  </section>

  <section class="panel">
    <div class="row"><h2>Self-discharge ranking</h2><span class="muted" id="rankinfo"></span></div>
    <div class="tbl" id="rank"></div>
  </section>

  <section class="panel">
    <div class="row"><h2>Latest runs</h2><a href="export.csv">Download CSV</a></div>
    <div class="runs" id="runs"></div>
  </section>
</div>
<script>
const COLORS=['#1f77b4','#d62728','#2ca02c','#9467bd','#ff7f0e','#17becf','#8c564b','#e377c2','#7f7f7f','#bcbd22'];
const $=s=>document.querySelector(s);
let rows=[],status={},cpm=12,nCells=0,sel=null,lastA=null,poll=null,packName='';
const fmt=t=>new Date(t*1000).toLocaleString(undefined,{weekday:'short',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
const nl=(v,d)=>v.toFixed(d);
const med=a=>{const s=[...a].sort((x,y)=>x-y),m=s.length>>1;return s.length?(s.length%2?s[m]:(s[m-1]+s[m])/2):NaN};
const grp=()=>cpm>0?cpm:Math.max(nCells,1);                // cells per group (whole pack when no modules)
const modOf=i=>Math.floor(i/grp())+1;
const nMods=()=>Math.ceil(nCells/grp());
const cellNo=i=>i%grp()+1;
const cellName=i=>cpm>0?`M${modOf(i)} · cell ${cellNo(i)}`:`Cell ${i+1}`;
const colOf=m=>COLORS[(m-1)%COLORS.length];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const store={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};

async function getJSON(u){const r=await fetch(u);if(r.status===401){location.href='login';throw new Error('not logged in');}return r.json();}
async function load(){
  try{
    const [d,s]=await Promise.all([getJSON('api/data'),getJSON('api/status')]);
    rows=d.rows;status=s;cpm=d.cells_per_module||0;packName=d.pack_name||'Battery pack';
    nCells=rows.length?Math.min(...rows.map(r=>r.d.length)):0;
    document.title=packName+' · CellDrift';$('#title').textContent=packName;
    if(sel===null){const saved=store.get('celldrift-sel');sel=new Set(saved?JSON.parse(saved):[...Array(nCells).keys()]);}
    sel=new Set([...sel].filter(i=>i<nCells));
    fillBase();render();
    if(status.busy&&!poll)poll=setInterval(refreshStatus,4000);
  }catch(e){$('#sub').textContent='Could not load the data: '+e;}
}
async function refreshStatus(){
  try{status=await getJSON('api/status');}catch(e){return;}
  renderHead();renderRuns();
  if(!status.busy){clearInterval(poll);poll=null;load();}
}
function saveSel(){store.set('celldrift-sel',JSON.stringify([...sel]));}
function fillBase(){
  const b=$('#base'),cur=b.value;
  b.innerHTML=rows.map((r,i)=>`<option value="${i}">${fmt(r.t)}</option>`).join('');
  b.value=(cur!==''&&+cur<rows.length)?cur:'0';
}
function analyze(){
  if(rows.length<2||!nCells)return null;
  const bi=Math.min(+$('#base').value||0,rows.length-2),b=rows[bi],l=rows[rows.length-1];
  const days=(l.t-b.t)/86400;
  const cells=Array.from({length:nCells},(_,i)=>({i,start:b.d[i],now:l.d[i],drop:b.d[i]-l.d[i]}));
  cells.forEach(c=>c.rate=days>0?c.drop/days:0);
  const mods={};cells.forEach(c=>(mods[modOf(c.i)]=mods[modOf(c.i)]||[]).push(c));
  Object.values(mods).forEach(list=>{const mr=med(list.map(c=>c.rate)),md=med(list.map(c=>c.drop));list.forEach(c=>{c.excess=c.rate-mr;c.exDrop=c.drop-md;});});
  cells.forEach(c=>{c.st=days<0.5?'x':(c.excess>=1&&c.exDrop>=3)?'b':(c.excess>=0.5&&c.exDrop>=2)?'w':'n';});
  return {bi,days,cells};
}
function renderHead(){
  const l=rows[rows.length-1];
  $('#sub').textContent=rows.length?`${rows.length} measurements · latest ${fmt(l.t)}`+(status.next_run?` · next ${fmt(status.next_run)}`:'')+(status.entity?` · switches ${status.entity}`:' · read only'):'No measurements yet. Click Measure now or wait for the next run.';
  const ctl=!!status.can_control;
  $('#now').hidden=!ctl;$('#setlink').hidden=!ctl;$('#logout').hidden=!status.auth_enabled;
  $('#now').disabled=!!status.busy;$('#now').textContent=status.busy?'Measuring…':'Measure now';
  $('#phase').textContent=status.busy?(status.phase||'busy')+'…':(ctl?'':'View only');
}
$('#logout').addEventListener('click',async e=>{e.preventDefault();await fetch('api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});location.href='login';});
function render(){
  const a=analyze();lastA=a;renderHead();
  const l=rows[rows.length-1];
  if(l&&nCells){const vals=l.d.slice(0,nCells),mn=Math.min(...vals),mx=Math.max(...vals),flagged=a?a.cells.filter(c=>c.st==='b').length:0;
    const temp=l.tmin!=null?`${nl(l.tmin,1)}–${nl(l.tmax,1)} °C`:'–';
    $('#stats').innerHTML=[['Lowest cell',mn+' mV'],['Highest cell',mx+' mV'],['Pack delta',(mx-mn)+' mV'],['Pack temp',temp],['Logged',a?nl(a.days,2)+' d':'–'],['Deviating',a?String(flagged):'–']].map(([k,v])=>`<div class="stat"><div class="k">${k}</div><div class="v" title="${v}">${v}</div></div>`).join('')
      +(l.b?`<div class="warnline">Note: ${l.b} cells were balancing at the last measurement. That disturbs a self-discharge test.</div>`:'');}
  else $('#stats').innerHTML='<span class="muted">No data yet.</span>';
  $('#modpanel').hidden=!(cpm>0&&nMods()>1);
  renderPicker(a);drawCells(a);drawMods(a);drawTemp();renderRank(a);renderRuns();
}
function renderPicker(a){
  const flag=new Set(a?a.cells.filter(c=>c.st==='b'||c.st==='w').map(c=>c.i):[]);
  const g=grp(),cols=Math.min(g,12);let h='';
  for(let m=1;m<=nMods();m++){
    h+=`<div class="mod" style="--c:${colOf(m)}"><span class="mname"><i></i><button data-m="${m}" style="padding:1px 6px;font-size:12px">${cpm>0?'M'+m:'All'}</button></span><div class="chips" style="--cols:${cols}">`;
    for(let i=(m-1)*g;i<Math.min(m*g,nCells);i++)h+=`<button class="chipcell${sel.has(i)?' on':''}${flag.has(i)?' flag':''}" data-i="${i}" title="${cellName(i)} (#${i+1} in the Battery Emulator)">${cellNo(i)}</button>`;
    h+='</div></div>';
  }
  $('#mods').innerHTML=h;$('#selcount').textContent=`(${sel.size} of ${nCells})`;
}
$('#mods').addEventListener('click',e=>{
  const b=e.target.closest('button');if(!b)return;
  if(b.dataset.i!==undefined){const i=+b.dataset.i;sel.has(i)?sel.delete(i):sel.add(i);}
  else if(b.dataset.m){const m=+b.dataset.m,ids=[...Array(nCells).keys()].filter(i=>modOf(i)===m),allOn=ids.every(i=>sel.has(i));ids.forEach(i=>allOn?sel.delete(i):sel.add(i));}
  saveSel();render();
});
document.querySelector('.quick').addEventListener('click',e=>{
  const q=e.target.dataset.q;if(!q)return;
  if(q==='all')sel=new Set([...Array(nCells).keys()]);
  if(q==='none')sel=new Set();
  if(q==='flag')sel=new Set(lastA?lastA.cells.filter(c=>c.st==='b'||c.st==='w').map(c=>c.i):[]);
  if(q==='low5')sel=new Set(lastA?[...lastA.cells].sort((x,y)=>y.excess-x.excess).slice(0,5).map(c=>c.i):[]);
  saveSel();render();
});
function renderRank(a){
  if(!a){$('#rank').innerHTML='<p class="muted">At least two measurements are needed.</p>';$('#rankinfo').textContent='';return;}
  $('#rankinfo').textContent=a.days<0.5?'Less than 12 hours logged: no verdict yet.':`${nl(a.days,2)} days since baseline · red = ≥1 mV/day and ≥3 mV more loss than the ${cpm>0?'module':'pack'} median`;
  const list=[...a.cells].sort((x,y)=>y.excess-x.excess),lbl={n:'normal',w:'watch',b:'deviating',x:'–'};
  $('#rank').innerHTML=`<table><thead><tr><th>Cell</th><th>Baseline</th><th>Now</th><th>Loss mV</th><th>mV/day</th><th>vs ${cpm>0?'module':'pack'}</th><th>Status</th></tr></thead><tbody>`+
    list.map(c=>`<tr data-i="${c.i}" class="${c.st}${sel.has(c.i)?' sel':''}"><td>${cellName(c.i)} <span class="muted" style="font-size:11px">#${c.i+1}</span></td><td class="num">${c.start}</td><td class="num">${c.now}</td><td class="num">${nl(c.drop,0)}</td><td class="num">${nl(c.rate,2)}</td><td class="num">${c.excess>=0?'+':''}${nl(c.excess,2)}</td><td><span class="pill ${c.st}">${lbl[c.st]}</span></td></tr>`).join('')+'</tbody></table>';
}
$('#rank').addEventListener('click',e=>{const tr=e.target.closest('tr[data-i]');if(!tr)return;const i=+tr.dataset.i;sel.has(i)?sel.delete(i):sel.add(i);saveSel();render();});
function renderRuns(){
  const r=status.runs||[];
  $('#runs').innerHTML=r.length?r.map(x=>`<div class="${x.ok?'':'err'}">${fmt(x.t)} · ${esc(x.message)}</div>`).join(''):'<span class="muted">No runs yet.</span>';
}

// ---- generic line chart
function niceStep(span){const raw=span/6,p=Math.pow(10,Math.floor(Math.log10(raw||1))),f=raw/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p;}
function lineChart(cv,series,o){
  const ctx=cv.getContext('2d'),dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  cv.width=W*dpr;cv.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
  const cs=getComputedStyle(document.documentElement),ink=cs.getPropertyValue('--muted'),line=cs.getPropertyValue('--line');
  cv._geo=null;
  const pts=series.flatMap(s=>s.p.filter(p=>p.v!=null));
  if(!pts.length){ctx.fillStyle=ink;ctx.font='14px system-ui';ctx.fillText(o.empty||'No data',16,28);return;}
  let lo=Math.min(...pts.map(p=>p.v)),hi=Math.max(...pts.map(p=>p.v));
  if(lo===hi){lo-=1;hi+=1;}
  const st=niceStep(hi-lo);lo=Math.floor(lo/st)*st;hi=Math.ceil(hi/st)*st;
  let t0=Math.min(...pts.map(p=>p.t)),t1=Math.max(...pts.map(p=>p.t));if(t1===t0)t1=t0+3600;
  const L=60,R=14,T=12,B=34,x=t=>L+(t-t0)/(t1-t0)*(W-L-R),y=v=>T+(hi-v)/(hi-lo)*(H-T-B);
  const dec=st<1?(st<0.1?2:1):0;
  ctx.font='11px ui-monospace,Consolas,monospace';ctx.fillStyle=ink;ctx.strokeStyle=line;ctx.lineWidth=1;
  for(let v=lo;v<=hi+1e-9;v+=st){ctx.beginPath();ctx.moveTo(L,y(v));ctx.lineTo(W-R,y(v));ctx.stroke();ctx.textAlign='right';ctx.fillText(nl(v,dec),L-6,y(v)+4);}
  const nt=Math.max(2,Math.min(8,Math.floor((W-L-R)/130)));
  for(let k=0;k<=nt;k++){const t=t0+(t1-t0)*k/nt;ctx.textAlign=k===0?'left':k===nt?'right':'center';ctx.fillText(new Date(t*1000).toLocaleString(undefined,{day:'numeric',month:'numeric',hour:'2-digit',minute:'2-digit'}),x(t),H-12);}
  ctx.save();ctx.translate(13,T+(H-T-B)/2);ctx.rotate(-Math.PI/2);ctx.textAlign='center';ctx.fillText(o.ylabel,0,0);ctx.restore();
  const dim=series.some(s=>s.strong);
  [...series].sort((p,q)=>(p.strong?1:0)-(q.strong?1:0)).forEach(s=>{
    ctx.strokeStyle=s.color;ctx.fillStyle=s.color;ctx.globalAlpha=s.strong||!dim?1:(o.dimAlpha??0.4);ctx.lineWidth=s.strong?2.6:(o.lw||1.2);
    ctx.setLineDash(s.dash||[]);ctx.beginPath();let pen=false;
    s.p.forEach(p=>{if(p.v==null){pen=false;return;}const px=x(p.t),py=y(p.v);pen?ctx.lineTo(px,py):ctx.moveTo(px,py);pen=true;});ctx.stroke();ctx.setLineDash([]);
    if(s.p.length<40)s.p.forEach(p=>{if(p.v==null)return;ctx.beginPath();ctx.arc(x(p.t),y(p.v),s.strong?2.6:1.6,0,7);ctx.fill();});
  });
  ctx.globalAlpha=1;cv._geo={x,y,series,fmtv:o.fmtv};
}
function attachTip(cv){
  const tip=cv.parentElement.querySelector('.tip');
  const show=e=>{
    const g=cv._geo;if(!g){tip.style.display='none';return;}
    const r=cv.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;let best=null,bd=1e9;
    g.series.forEach(s=>s.p.forEach(p=>{if(p.v==null)return;const d=Math.hypot(g.x(p.t)-mx,(g.y(p.v)-my)*1.5);if(d<bd){bd=d;best={s,p};}}));
    if(!best||bd>60){tip.style.display='none';return;}
    tip.innerHTML=`<b>${best.s.label}</b><br>${fmt(best.p.t)}<br>${g.fmtv(best.p.v,best.p)}`;
    tip.style.display='block';tip.style.left=Math.max(0,Math.min(mx+12,r.width-190))+'px';tip.style.top=(my+12)+'px';
  };
  cv.addEventListener('pointermove',show);
  cv.addEventListener('pointerdown',show);
  cv.addEventListener('pointerleave',e=>{if(e.pointerType==='mouse')tip.style.display='none';});
  document.addEventListener('pointerdown',e=>{if(e.target!==cv)tip.style.display='none';});
}
function drawCells(a){
  const mode=$('#mode').value,bi=a?a.bi:0;
  const flag=new Set(a?a.cells.filter(c=>c.st==='b'||c.st==='w').map(c=>c.i):[]);
  const series=rows.length?[...sel].sort((p,q)=>p-q).map(i=>({label:`${cellName(i)} <span style="opacity:.6">#${i+1}</span>`,color:colOf(modOf(i)),strong:flag.has(i),
    p:rows.map(r=>({t:r.t,v:r.d[i]==null?null:(mode==='delta'?r.d[i]-rows[bi].d[i]:r.d[i]),raw:r.d[i]}))})):[];
  lineChart($('#c-cells'),series,{ylabel:mode==='delta'?'mV vs baseline':'mV',empty:rows.length?'No cells selected':'No measurements yet',lw:1.1,dimAlpha:sel.size>24?0.35:0.6,
    fmtv:(v,p)=>`${p.raw} mV`+(mode==='delta'?` (${v>=0?'+':''}${v})`:'')});
}
function drawMods(a){
  if(!(cpm>0&&nMods()>1)){$('#legend-mods').innerHTML='';return;}
  const mode=$('#mode').value,bi=a?a.bi:0,g=grp();
  const sum=(r,m)=>r.d.slice((m-1)*g,Math.min(m*g,nCells)).reduce((s,v)=>s+v,0);
  const series=rows.length?Array.from({length:nMods()},(_,k)=>{const m=k+1;return {label:`Module ${m}`,color:colOf(m),
    p:rows.map(r=>({t:r.t,v:mode==='delta'?sum(r,m)-sum(rows[bi],m):sum(r,m)/1000,raw:sum(r,m)}))};}):[];
  $('#modinfo').textContent=mode==='delta'?`sum of ${g} cells, change since baseline in mV`:`sum of ${g} cells in V`;
  lineChart($('#c-mods'),series,{ylabel:mode==='delta'?'mV vs baseline':'V',empty:'No measurements yet',lw:1.8,
    fmtv:(v,p)=>`${nl(p.raw/1000,3)} V`+(mode==='delta'?` (${v>=0?'+':''}${v} mV)`:'')});
  $('#legend-mods').innerHTML=series.map(s=>`<span style="--c:${s.color}">${s.label}</span>`).join('');
}
function drawTemp(){
  const defs=[['tmin','Pack min','#1f77b4'],['tmax','Pack max','#d62728']];
  const series=defs.filter(([k])=>rows.some(r=>r[k]!=null)).map(([k,label,color])=>({label,color,p:rows.map(r=>({t:r.t,v:r[k]}))}));
  lineChart($('#c-temp'),series,{ylabel:'°C',empty:'No temperature data yet',lw:2,fmtv:v=>`${nl(v,1)} °C`});
  $('#legend-temp').innerHTML=series.map(s=>`<span style="--c:${s.color}">${s.label}</span>`).join('');
}
['#c-cells','#c-mods','#c-temp'].forEach(s=>attachTip($(s)));
['#mode','#base'].forEach(s=>$(s).addEventListener('change',render));
let lastW=0,rafId=0;
new ResizeObserver(()=>{const w=document.querySelector('.wrap').clientWidth;if(w===lastW)return;lastW=w;cancelAnimationFrame(rafId);rafId=requestAnimationFrame(()=>{drawCells(lastA);drawMods(lastA);drawTemp();});}).observe(document.querySelector('.wrap'));
$('#now').addEventListener('click',async()=>{
  $('#now').disabled=true;$('#phase').textContent='starting…';
  try{const r=await fetch('api/measure',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    if(r.status===409)$('#phase').textContent='a measurement is already running';
    else if(r.status===401)location.href='login';
    else if(!r.ok){const j=await r.json().catch(()=>({}));$('#phase').textContent=j.message||'could not start';}
  }catch(e){$('#phase').textContent='could not start';}
  if(!poll)poll=setInterval(refreshStatus,4000);
});
load();setInterval(()=>{if(!poll)load();},60000);
</script></body></html>"""


SETTINGS_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>CellDrift · settings</title>
<style>""" + STYLE_BASE + r"""
body{line-height:1.5}
.wrap{max-width:760px;margin:0 auto;padding:18px 16px 40px;display:grid;gap:16px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
.panel{padding:18px;gap:14px}
.panel.danger{border-color:var(--bad)}
form{display:grid;gap:14px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:560px){.grid2{grid-template-columns:1fr}}
label{display:grid;gap:4px;font-weight:600;font-size:13px}
label small{font-weight:400;color:var(--muted)}
input{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;width:100%}
input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.btns{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
button{font:inherit;font-weight:600;border-radius:6px;padding:9px 16px;cursor:pointer;border:1px solid var(--accent);background:var(--accent);color:var(--panel)}
button.ghost{background:transparent;color:var(--accent)}
button.red{background:var(--bad);border-color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
.msg{font-size:14px}.msg.ok{color:var(--ok)}.msg.err{color:var(--bad)}
h3{margin:6px 0 0;font-size:15px}
</style></head><body>
<div class="wrap">
  <div class="btns" style="justify-content:space-between"><h1>Settings</h1><a href="./">← Back to measurements</a></div>

  <section class="panel">
    <form id="cfg" novalidate>
      <h2>Battery</h2>
      <div class="grid2">
        <label>Pack name<small>Shown as the page title.</small><input id="pack_name" type="text" maxlength="60" required></label>
        <label>Interval (minutes)<small>Time between measurements. 60 = every full hour.</small><input id="interval_minutes" type="number" min="1" max="1440" required></label>
      </div>
      <h3>Battery Emulator</h3>
      <div class="grid2">
        <label>Address<small>Web interface of the emulator, e.g. http://192.168.1.100</small><input id="emulator_url" type="text" autocomplete="off" required></label>
        <label>Battery number<small>1, or 2 for the second battery of a double-battery setup.</small><input id="battery_index" type="number" min="1" max="4" required></label>
      </div>
      <div class="btns"><button type="button" class="ghost" id="emutest">Test emulator</button><span class="msg" id="emumsg" role="status"></span></div>
      <h3>Cell layout</h3>
      <div class="grid2">
        <label>Number of cells<small>0 = automatic (whatever the emulator reports). A measurement only counts when exactly this many cells are reported.</small><input id="expected_cells" type="number" min="0" max="1000" required></label>
        <label>Cells per module<small>Groups cells per module for the charts and the ranking. 0 = no modules.</small><input id="cells_per_module" type="number" min="0" max="1000" required></label>
        <label>Lowest valid cell voltage (mV)<small>Readings below this mean "not ready yet". Li-ion/NMC ≈ 2500, LFP ≈ 2000.</small><input id="min_mv" type="number" min="500" max="5000" required></label>
        <label>Highest valid cell voltage (mV)<small>Readings above this mean "not ready yet". Usually 4300–4500.</small><input id="max_mv" type="number" min="500" max="5000" required></label>
      </div>
      <h3>Home Assistant (optional)</h3>
      <p class="muted" style="margin:0">Switches a smart plug or relay on before each measurement and off afterwards. Leave the entity empty to only read the emulator.</p>
      <div class="grid2">
        <label>Home Assistant address<small>e.g. https://192.168.1.10:8123</small><input id="ha_url" type="text" autocomplete="off"></label>
        <label>Entity to switch<small>e.g. switch.battery_emulator</small><input id="ha_entity" type="text" autocomplete="off"></label>
      </div>
      <label>Long-lived access token<small id="tokhint">Loading…</small><input id="ha_token" type="password" autocomplete="new-password" placeholder="Leave empty to keep the current token"></label>
      <div class="btns">
        <button type="submit">Save settings</button>
        <button type="button" class="ghost" id="hatest">Test Home Assistant</button>
        <span class="msg" id="cfgmsg" role="status"></span>
      </div>
    </form>
  </section>

  <section class="panel">
    <h2>Access</h2>
    <p style="margin:0" id="accessinfo" class="muted">Loading…</p>
    <form id="pwform" novalidate>
      <label style="display:flex;gap:8px;align-items:center;font-weight:600"><input id="pwon" type="checkbox" style="width:auto"> Require a password</label>
      <p style="margin:0" class="muted" id="pwexplain"></p>
      <label id="curwrap">Current password<small>Needed to change anything about access.</small><input id="pwcur" type="password" autocomplete="current-password"></label>
      <div class="grid2">
        <label>New password<small>Any length. Leave empty to keep the current one.</small><input id="pwnew" type="password" autocomplete="new-password"></label>
        <label>Repeat new password<input id="pwnew2" type="password" autocomplete="new-password"></label>
      </div>
      <div class="btns"><button type="submit">Save access</button><span class="msg" id="pwmsg" role="status"></span></div>
    </form>
  </section>

  <section class="panel danger">
    <h2>Clear data</h2>
    <p style="margin:0">Removes all measurements and runs. A backup of the database is made next to it first. <span class="muted" id="counts"></span></p>
    <div class="btns"><button type="button" class="ghost" id="ask">Remove all data…</button></div>
    <div id="confirm" hidden>
      <label>Type CLEAR to confirm<input id="confirmtxt" type="text" autocomplete="off"></label>
      <div class="btns" style="margin-top:10px">
        <button type="button" class="red" id="clear" disabled>Remove permanently</button>
        <button type="button" class="ghost" id="cancel">Cancel</button>
      </div>
    </div>
    <span class="msg" id="clrmsg" role="status"></span>
  </section>
</div>
<script>
const $=s=>document.querySelector(s);
const FIELDS=['pack_name','interval_minutes','emulator_url','battery_index','expected_cells','cells_per_module','min_mv','max_mv','ha_url','ha_entity'];
function msg(el,t,ok){el.textContent=t;el.className='msg '+(ok?'ok':'err');}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});if(r.status===401){location.href='login';return {ok:false};}let j={};try{j=await r.json()}catch(e){}return {ok:r.ok,...j};}
const EXPLAIN={on:'On: everyone has to log in first, also on the local network.',off:'Off: anyone with the address can view the charts. Measuring, settings and clearing data are then only possible from the local network.'};
$('#pwon').addEventListener('change',e=>{$('#pwexplain').textContent=e.target.checked?EXPLAIN.on:EXPLAIN.off;});
async function load(){
  const r0=await fetch('api/config');
  if(r0.status===401){location.href='login';return;}
  if(r0.status===403){location.href='./';return;}
  const c=await r0.json();
  FIELDS.forEach(k=>{$('#'+k).value=c[k]??'';});
  $('#tokhint').textContent=c.token_set?'A token is set. Fill in only to replace it; the current one is never shown.':'No token set. Create one in Home Assistant: Profile → Security → Long-lived access tokens.';
  $('#pwon').checked=c.auth_enabled;$('#pwexplain').textContent=c.auth_enabled?EXPLAIN.on:EXPLAIN.off;
  $('#curwrap').hidden=!c.password_set;
  $('#accessinfo').textContent=`Connection: ${c.https?'HTTPS (encrypted)':'HTTP (not encrypted — do not use a password over the internet)'} · you are ${c.lan?'on the local network':'on the internet'} · password ${c.auth_enabled?'on':'off'}${c.password_set?'':' (no password set yet)'}.`;
  $('#counts').textContent=`Now: ${c.measurements} measurements, ${c.runs} runs.`;
}
$('#cfg').addEventListener('submit',async e=>{
  e.preventDefault();
  const body={ha_token:$('#ha_token').value};FIELDS.forEach(k=>body[k]=$('#'+k).value);
  const r=await post('api/config',body);
  msg($('#cfgmsg'),r.message||'Saving failed.',r.ok);
  if(r.ok){$('#ha_token').value='';load();}
});
$('#emutest').addEventListener('click',async()=>{
  msg($('#emumsg'),'Testing…',true);
  const r=await post('api/emulator-test',{emulator_url:$('#emulator_url').value,battery_index:$('#battery_index').value});
  msg($('#emumsg'),r.message||'Test failed.',r.ok);
  if(r.ok&&r.cells&&+$('#expected_cells').value===0)$('#emumsg').textContent+=` Tip: set "Number of cells" to ${r.cells} so incomplete readings are never stored.`;
});
$('#hatest').addEventListener('click',async()=>{msg($('#cfgmsg'),'Testing…',true);const r=await post('api/ha-test');msg($('#cfgmsg'),r.message||'Test failed.',r.ok);});
$('#pwform').addEventListener('submit',async e=>{
  e.preventDefault();
  if($('#pwnew').value!==$('#pwnew2').value){msg($('#pwmsg'),'The two new passwords are not the same.',false);return;}
  const r=await post('api/password',{enabled:$('#pwon').checked,current:$('#pwcur').value,new:$('#pwnew').value});
  msg($('#pwmsg'),r.message||'Saving failed.',r.ok);
  if(r.ok){['#pwcur','#pwnew','#pwnew2'].forEach(s=>$(s).value='');load();}
});
$('#ask').addEventListener('click',()=>{$('#confirm').hidden=false;$('#ask').hidden=true;$('#confirmtxt').focus();});
$('#cancel').addEventListener('click',()=>{$('#confirm').hidden=true;$('#ask').hidden=false;$('#confirmtxt').value='';$('#clear').disabled=true;});
$('#confirmtxt').addEventListener('input',e=>{$('#clear').disabled=e.target.value.trim()!=='CLEAR';});
$('#clear').addEventListener('click',async()=>{
  $('#clear').disabled=true;
  const r=await post('api/clear',{confirm:$('#confirmtxt').value.trim()});
  msg($('#clrmsg'),r.message||'Clearing failed.',r.ok);
  if(r.ok){$('#cancel').click();load();}
});
load();
</script></body></html>"""


LOGIN_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>CellDrift · log in</title>
<style>""" + STYLE_BASE + r"""
body{font-size:15px;min-height:100vh;display:grid;place-items:center;padding:16px}
form{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:24px;width:min(360px,100%);display:grid;gap:14px}
input{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 10px;width:100%}
button{font:inherit;font-weight:600;border-radius:6px;padding:10px;cursor:pointer;border:1px solid var(--accent);background:var(--accent);color:var(--panel)}
#msg{color:var(--bad);min-height:1.5em;font-size:14px}
</style></head><body>
<form id="f">
  <h1 style="font-size:22px">CellDrift</h1>
  <label for="pw">Password</label>
  <input id="pw" type="password" autocomplete="current-password" autofocus required>
  <button type="submit">Log in</button>
  <div id="msg" role="status"></div>
</form>
<script>
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const r=await fetch('api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
  if(r.ok){location.href='./';return;}
  const j=await r.json().catch(()=>({}));
  document.getElementById('msg').textContent=j.message||'Login failed.';
});
</script></body></html>"""

FORBIDDEN_PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CellDrift</title>
<style>body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#eef1f3;color:#17212b;padding:40px 16px;text-align:center}
@media (prefers-color-scheme:dark){body{background:#11171c;color:#e4eaee}}a{color:inherit}</style></head>
<body><h1>View only</h1><p>Settings are only available from the local network, or turn on a password.</p>
<p><a href="./">Back to the measurements</a></p></body></html>"""


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.json", help="JSON config file (default: config.json, created when missing)")
    ap.add_argument("--once", action="store_true", help="do one measurement and exit")
    ap.add_argument("--no-initial", action="store_true", help="do not measure right after starting")
    args = ap.parse_args()

    if not os.path.exists(args.config):
        write_default_config(args.config)
        log(f"created {os.path.abspath(args.config)} with default settings; open the web page to configure")
    cfg = load_config(args.config)
    con = open_db(cfg["db_path"])

    if switching(cfg):
        if not ha_token(cfg):
            log("NOTE: no Home Assistant access token yet; switching will fail until one is set")
        else:
            try:
                log(f"Home Assistant reachable, {cfg['ha_entity']} is now: {ha_state(cfg, cfg['ha_entity'])}")
            except Exception as exc:
                log(f"NOTE: Home Assistant not reachable or entity unknown: {exc}")
    else:
        log("Home Assistant switching is off: only reading the emulator")
    if args.once:
        ok, _ = measure_once(cfg, con, source="once")
        sys.exit(0 if ok else 1)

    threading.Thread(target=scheduler, args=(cfg, con, not args.no_initial), daemon=True).start()
    addr = (cfg["http_host"], cfg["http_port"])
    if os.path.exists(cfg["tls_cert"]) and os.path.exists(cfg["tls_key"]):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
        srv = TLSServer(addr, make_handler(cfg, con), ctx)
        cfg["_https"] = True
    else:
        srv = ThreadingHTTPServer(addr, make_handler(cfg, con))
        srv.daemon_threads = True
        cfg["_https"] = False
        log("NOTE: no TLS certificate found (run make_cert.sh); the web page runs without HTTPS")
    scheme = "https" if cfg["_https"] else "http"
    log(f"web page on {scheme}://{cfg['http_host']}:{cfg['http_port']}/  "
        f"(password {'on' if cfg['auth_enabled'] else 'off'}, Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("stopped")


if __name__ == "__main__":
    main()
