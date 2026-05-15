"""
Database layer — SQLite via stdlib sqlite3
No external ORM required; zero dependencies.
"""

import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict


class Database:
    DB_PATH = "phishing_detector.db"

    def init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    url              TEXT    NOT NULL,
                    ml_probability   REAL,
                    vt_malicious     INTEGER,
                    vt_total         INTEGER,
                    final_verdict    TEXT,
                    risk_level       TEXT,
                    confidence_score REAL,
                    indicators       TEXT,
                    vt_engines       TEXT,
                    mitre_technique  TEXT,
                    timestamp        TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        print("[DB] ✅ Database initialised")

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_scan(
        self,
        url:        str,
        ml_result:  dict,
        vt_result:  Optional[dict],
        final:      dict,
    ) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans
                    (url, ml_probability, vt_malicious, vt_total,
                     final_verdict, risk_level, confidence_score,
                     indicators, vt_engines, mitre_technique, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    ml_result.get("phishing_probability"),
                    vt_result.get("malicious", 0)  if vt_result else None,
                    vt_result.get("total", 0)       if vt_result else None,
                    final["verdict"],
                    final["risk_level"],
                    final["confidence_score"],
                    json.dumps(ml_result.get("top_indicators", [])),
                    json.dumps(vt_result.get("flagged_engines", []) if vt_result else []),
                    final.get("mitre_technique"),
                    datetime.utcnow().isoformat(),
                ),
            )
            return cur.lastrowid

    def clear_history(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_history(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with self._conn() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            phishing  = conn.execute("SELECT COUNT(*) FROM scans WHERE final_verdict='PHISHING'").fetchone()[0]
            suspicious= conn.execute("SELECT COUNT(*) FROM scans WHERE final_verdict='SUSPICIOUS'").fetchone()[0]
            safe      = conn.execute("SELECT COUNT(*) FROM scans WHERE final_verdict='SAFE'").fetchone()[0]

            recent = conn.execute("""
                SELECT date(timestamp) day,
                       COUNT(*) total,
                       SUM(CASE WHEN final_verdict='PHISHING'   THEN 1 ELSE 0 END) phishing,
                       SUM(CASE WHEN final_verdict='SUSPICIOUS' THEN 1 ELSE 0 END) suspicious
                FROM scans
                WHERE timestamp > datetime('now','-14 days')
                GROUP BY date(timestamp)
                ORDER BY day
            """).fetchall()

            top_threats = conn.execute("""
                SELECT url, confidence_score, timestamp
                FROM scans
                WHERE final_verdict = 'PHISHING'
                ORDER BY confidence_score DESC
                LIMIT 10
            """).fetchall()

        return {
            "total_scans":        total,
            "phishing_detected":  phishing,
            "suspicious_detected":suspicious,
            "safe_detected":      safe,
            "threat_rate":        round(phishing / max(total, 1) * 100, 1),
            "recent_activity":    [{"day": r[0], "total": r[1], "phishing": r[2], "suspicious": r[3]}
                                   for r in recent],
            "top_threats":        [{"url": t[0], "score": t[1], "time": t[2]}
                                   for t in top_threats],
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.DB_PATH)
