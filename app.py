from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent
DB = ROOT / "siems.db"
PORT = 8000

SUSPICIOUS = [
    ("SQL_INJECTION", re.compile(r"(?:union\s+select|select\s+.+\s+from|\bor\s+['\"]?\d|--|%27|%3d)", re.I), "Possível tentativa de SQL injection"),
    ("XSS_ATTEMPT", re.compile(r"(?:<script|javascript:|onerror\s*=|%3cscript)", re.I), "Possível tentativa de XSS"),
    ("PATH_TRAVERSAL", re.compile(r"(?:\.\./|%2e%2e%2f|/etc/passwd|\\windows\\)", re.I), "Tentativa de acesso a caminho restrito"),
]
SCAN_PATHS = re.compile(r"(?:/\.env|/wp-admin|/wp-login|/phpmyadmin|/\.git|/etc/passwd|/config\.php)", re.I)


def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            ip TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
            status INTEGER NOT NULL, user_agent TEXT DEFAULT '', raw TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            severity TEXT NOT NULL, kind TEXT NOT NULL, ip TEXT NOT NULL,
            message TEXT NOT NULL, event_id INTEGER,
            status TEXT NOT NULL DEFAULT 'Novo', note TEXT NOT NULL DEFAULT '',
            updated_at TEXT
        );
        """)
        # Migração simples para bancos criados por versões anteriores do protótipo.
        columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
        if "status" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'Novo'")
        if "note" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN note TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN updated_at TEXT")


def make_alert(db, kind, ip, message, severity="Alta", event_id=None):
    db.execute("INSERT INTO alerts(created_at,severity,kind,ip,message,event_id) VALUES(?,?,?,?,?,?)",
               (datetime.now(timezone.utc).isoformat(), severity, kind, ip, message, event_id))


def process_event(event):
    ip = str(event.get("ip", "unknown"))[:100]
    method = str(event.get("method", "GET")).upper()[:12]
    path = str(event.get("path", "/"))[:2000]
    agent = str(event.get("user_agent", ""))[:500]
    try:
        status = int(event.get("status", 200))
        if not 100 <= status <= 599: raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("status deve ser um código HTTP entre 100 e 599")
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        cur = db.execute("INSERT INTO events(created_at,ip,method,path,status,user_agent,raw) VALUES(?,?,?,?,?,?,?)",
                         (now, ip, method, path, status, agent, str(event.get("raw", ""))[:4000]))
        event_id = cur.lastrowid
        for kind, pattern, message in SUSPICIOUS:
            if pattern.search(path):
                make_alert(db, kind, ip, message, "Crítica", event_id)
        if SCAN_PATHS.search(path):
            make_alert(db, "PATH_SCAN", ip, f"Acesso a caminho frequentemente sondado: {path[:180]}", "Média", event_id)
        # Heurística: vários erros 404 da mesma origem em cinco minutos.
        if status == 404:
            since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
            count = db.execute("SELECT COUNT(*) FROM events WHERE ip=? AND status=404 AND created_at>=?", (ip, since)).fetchone()[0]
            already = db.execute("SELECT 1 FROM alerts WHERE ip=? AND kind='HTTP_404_SCAN' AND created_at>=?", (ip, since)).fetchone()
            if count >= 10 and not already:
                make_alert(db, "HTTP_404_SCAN", ip, f"Possível varredura: {count} respostas 404 em cinco minutos", "Alta", event_id)
        # Heurística didática: 8+ requisições em 60 s a rotas de autenticação.
        if re.search(r"login|signin|auth", path, re.I):
            since = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            count = db.execute("SELECT COUNT(*) FROM events WHERE ip=? AND path LIKE '%login%' AND created_at>=?", (ip, since)).fetchone()[0]
            already = db.execute("SELECT 1 FROM alerts WHERE ip=? AND kind='AUTH_BURST' AND created_at>=?", (ip, since)).fetchone()
            if count >= 8 and not already:
                make_alert(db, "AUTH_BURST", ip, f"Muitas requisições a rota de autenticação ({count} em 60 s)", "Alta", event_id)
        return event_id


class Handler(BaseHTTPRequestHandler):
    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers(); self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); self.send_header("Access-Control-Allow-Headers", "Content-Type"); self.end_headers()

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/health": return self.send_json({"ok": True, "name": "SIEMS"})
        if route == "/api/alerts":
            with connect() as db: rows = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
            return self.send_json([dict(x) for x in rows])
        if route == "/api/events":
            with connect() as db: rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall()
            return self.send_json([dict(x) for x in rows])
        if route == "/api/summary":
            with connect() as db:
                events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                active = db.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE created_at>=?", ((datetime.now(timezone.utc)-timedelta(hours=24)).isoformat(),)).fetchone()[0]
            return self.send_json({"events": events, "alerts": alerts, "active_ips_24h": active})
        if route == "/":
            data = (ROOT / "index.html").read_bytes(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(data))); self.end_headers(); return self.wfile.write(data)
        self.send_json({"error": "rota não encontrada"}, 404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/logs": return self.send_json({"error": "rota não encontrada"}, 404)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 100_000: return self.send_json({"error": "payload excede 100 KB"}, 413)
            payload = json.loads(self.rfile.read(size))
            items = payload if isinstance(payload, list) else [payload]
            if not items or len(items) > 500: return self.send_json({"error": "envie de 1 a 500 eventos por vez"}, 400)
            ids = [process_event(x) for x in items]
            self.send_json({"received": len(ids), "event_ids": ids}, 201)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def do_PATCH(self):
        match = re.fullmatch(r"/api/alerts/(\d+)", urlparse(self.path).path)
        if not match: return self.send_json({"error": "rota não encontrada"}, 404)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 5000: return self.send_json({"error": "payload excede 5 KB"}, 413)
            payload = json.loads(self.rfile.read(size))
            allowed = {"Novo", "Em análise", "Positivo", "Resolvido", "Falso positivo"}
            status = payload.get("status")
            note = payload.get("note")
            if status not in allowed: return self.send_json({"error": "status de triagem inválido"}, 400)
            if note is not None and not isinstance(note, str): return self.send_json({"error": "note deve ser texto"}, 400)
            note = (note or "")[:1000]
            with connect() as db:
                cur = db.execute("UPDATE alerts SET status=?, note=?, updated_at=? WHERE id=?",
                                 (status, note, datetime.now(timezone.utc).isoformat(), int(match.group(1))))
                if cur.rowcount == 0: return self.send_json({"error": "alerta não encontrado"}, 404)
            return self.send_json({"ok": True, "id": int(match.group(1)), "status": status})
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")


if __name__ == "__main__":
    initialize()
    print(f"SIEMS disponível em http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
