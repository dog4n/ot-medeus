"""Workspace kalıcılığı + taramalar arası diff (SQLite).

Gerçek Osmedeus mantığının ürün değeri burada: her tarama kaydedilir ve
bir önceki taramayla karşılaştırılır. "Yeni cihaz çıktı", "yeni OT portu
açıldı", "cihaz kayboldu" → alarm üretilecek sinyaller.

Şema kasıtlı olarak sade tutuldu; FastAPI+PostgreSQL SaaS'a taşırken
tablolar birebir karşılık bulur (scans / hosts / services). SQLite burada
standalone/yerel kullanım ve test içindir.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    workflow    TEXT NOT NULL,
    profile     TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    parameters  TEXT,
    total_scanned INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    ip          TEXT NOT NULL,
    mac         TEXT,
    vendor      TEXT,
    source      TEXT,
    is_ot       INTEGER DEFAULT 0,
    shodan      TEXT,
    data        TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_ws ON scans(workspace);
"""


@dataclass
class ScanDiff:
    previous_scan_id: int | None
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_services: dict[str, list[str]] = field(default_factory=dict)      # ip -> [svc keys]
    removed_services: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_hosts or self.removed_hosts
                    or self.new_services or self.removed_services)


class Store:
    def __init__(self, db_path: str | Path):
        self.path = str(db_path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- yazma --------------------------------------------------------------
    def save_scan(self, result: ScanResult) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans(workspace, workflow, profile, started_at, "
            "finished_at, parameters, total_scanned) VALUES (?,?,?,?,?,?,?)",
            (result.workspace, result.workflow, result.profile, result.started_at,
             result.finished_at, json.dumps(result.parameters, ensure_ascii=False),
             result.total_scanned),
        )
        scan_id = cur.lastrowid
        for h in result.hosts:
            self.conn.execute(
                "INSERT INTO hosts(scan_id, ip, mac, vendor, source, is_ot, shodan, data) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, h.ip, h.mac, h.vendor, h.source, int(h.is_ot_candidate),
                 json.dumps(h.shodan, ensure_ascii=False),
                 json.dumps(h.to_dict(), ensure_ascii=False)),
            )
        self.conn.commit()
        return scan_id

    # -- okuma --------------------------------------------------------------
    def scan_ids(self, workspace: str) -> list[int]:
        rows = self.conn.execute(
            "SELECT id FROM scans WHERE workspace=? ORDER BY id DESC", (workspace,)
        ).fetchall()
        return [r["id"] for r in rows]

    def previous_scan_id(self, workspace: str, before_id: int) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE workspace=? AND id<? ORDER BY id DESC LIMIT 1",
            (workspace, before_id),
        ).fetchone()
        return row["id"] if row else None

    def _host_map(self, scan_id: int) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT ip, data FROM hosts WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return {r["ip"]: json.loads(r["data"]) for r in rows}

    # -- diff ---------------------------------------------------------------
    @staticmethod
    def _service_keys(host: dict) -> set[str]:
        keys = {f"{s['protocol']}/{s['port']}" for s in host.get("services", [])}
        keys |= {f"WEB/{w['port']}" for w in host.get("web_panels", [])}
        return keys

    def diff(self, workspace: str, scan_id: int) -> ScanDiff:
        prev_id = self.previous_scan_id(workspace, scan_id)
        d = ScanDiff(previous_scan_id=prev_id)
        if prev_id is None:
            return d

        cur = self._host_map(scan_id)
        prev = self._host_map(prev_id)

        d.new_hosts = sorted(set(cur) - set(prev))
        d.removed_hosts = sorted(set(prev) - set(cur))

        for ip in sorted(set(cur) & set(prev)):
            now_keys = self._service_keys(cur[ip])
            was_keys = self._service_keys(prev[ip])
            added = sorted(now_keys - was_keys)
            gone = sorted(was_keys - now_keys)
            if added:
                d.new_services[ip] = added
            if gone:
                d.removed_services[ip] = gone
        return d
