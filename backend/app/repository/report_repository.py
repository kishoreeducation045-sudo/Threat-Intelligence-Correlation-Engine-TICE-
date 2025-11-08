import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class ReportRepository:
    def __init__(
        self,
        db_path: str,
        retention_days: int = 7,
        retention_limit: int = 1000,
    ) -> None:
        self.db_path = Path(db_path)
        self.retention_days = retention_days
        self.retention_limit = retention_limit
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    threat_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    abuse_confidence REAL NOT NULL,
                    total_reports INTEGER,
                    categories TEXT NOT NULL,
                    triggered_rules TEXT NOT NULL,
                    narrative TEXT,
                    country TEXT,
                    asn TEXT,
                    raw_data TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_analyzed_at ON reports(analyzed_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_ip ON reports(ip_address)"
            )
            conn.commit()

    def save_analysis(
        self,
        *,
        ip_address: str,
        threat_score: int,
        risk_level: str,
        abuse_confidence: float,
        total_reports: int,
        categories: List[str],
        triggered_rules: List[str],
        narrative: str,
        country: str,
        asn: str,
        raw_data: Dict[str, Any],
        analyzed_at: Optional[datetime] = None,
    ) -> None:
        analyzed_at = analyzed_at or datetime.now(timezone.utc)
        record = (
            ip_address,
            analyzed_at.isoformat(),
            int(threat_score),
            risk_level,
            float(abuse_confidence),
            int(total_reports),
            json.dumps(categories or []),
            json.dumps(triggered_rules or []),
            narrative or "",
            country or "Unknown",
            asn or "Unknown",
            json.dumps(raw_data or {}),
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO reports (
                    ip_address,
                    analyzed_at,
                    threat_score,
                    risk_level,
                    abuse_confidence,
                    total_reports,
                    categories,
                    triggered_rules,
                    narrative,
                    country,
                    asn,
                    raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                record,
            )
            self._apply_retention(conn)
            conn.commit()

    def _apply_retention(self, conn: sqlite3.Connection) -> None:
        if self.retention_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
            conn.execute(
                "DELETE FROM reports WHERE datetime(analyzed_at) < datetime(?)",
                (cutoff.isoformat(),),
            )
        if self.retention_limit > 0:
            conn.execute(
                """
                DELETE FROM reports
                WHERE id NOT IN (
                    SELECT id FROM reports
                    ORDER BY datetime(analyzed_at) DESC
                    LIMIT ?
                )
                """,
                (self.retention_limit,),
            )

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    r.*,
                    (
                        SELECT COUNT(*)
                        FROM reports sub
                        WHERE sub.ip_address = r.ip_address
                    ) AS occurrence_count,
                    (
                        SELECT MIN(datetime(sub.analyzed_at))
                        FROM reports sub
                        WHERE sub.ip_address = r.ip_address
                    ) AS first_seen
                FROM reports r
                ORDER BY datetime(r.analyzed_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            categories = json.loads(row["categories"]) if row["categories"] else []
            triggered = json.loads(row["triggered_rules"]) if row["triggered_rules"] else []
            raw_data = json.loads(row["raw_data"]) if row["raw_data"] else {}
            analyzed_at = datetime.fromisoformat(row["analyzed_at"])
            first_seen = (
                datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else analyzed_at
            )
            occurrence = int(row["occurrence_count"] or 0)
            results.append(
                {
                    "id": row["id"],
                    "ip_address": row["ip_address"],
                    "analyzed_at": analyzed_at.isoformat(),
                    "threat_score": row["threat_score"],
                    "risk_level": row["risk_level"],
                    "abuse_confidence": row["abuse_confidence"],
                    "total_reports": row["total_reports"],
                    "categories": categories,
                    "triggered_rules": triggered,
                    "narrative": row["narrative"],
                    "country": row["country"],
                    "asn": row["asn"],
                    "raw_data": raw_data,
                    "occurrence_count": occurrence,
                    "is_new": occurrence <= 1 and analyzed_at == first_seen,
                }
            )
        return results

    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        with self._connect() as conn:
            top_risks_rows = conn.execute(
                """
                SELECT ip_address, threat_score, risk_level, abuse_confidence, analyzed_at,
                       (
                           SELECT COUNT(*)
                           FROM reports sub
                           WHERE sub.ip_address = reports.ip_address
                       ) AS occurrence_count
                FROM reports
                ORDER BY threat_score DESC, datetime(analyzed_at) DESC
                LIMIT 5
                """
            ).fetchall()

            risk_counts_rows = conn.execute(
                """
                SELECT risk_level, COUNT(*) as count
                FROM reports
                WHERE datetime(analyzed_at) >= datetime(?)
                GROUP BY risk_level
                """,
                (cutoff.isoformat(),),
            ).fetchall()

            volume_rows = conn.execute(
                """
                SELECT strftime('%Y-%m-%dT%H:00:00', analyzed_at) as bucket, COUNT(*) as count
                FROM reports
                WHERE datetime(analyzed_at) >= datetime(?)
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT 24
                """,
                (cutoff.isoformat(),),
            ).fetchall()

            total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            distinct_ips = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM reports").fetchone()[0]
            last_row = conn.execute(
                "SELECT analyzed_at FROM reports ORDER BY datetime(analyzed_at) DESC LIMIT 1"
            ).fetchone()
            category_rows = conn.execute(
                "SELECT categories FROM reports WHERE datetime(analyzed_at) >= datetime(?)",
                (cutoff.isoformat(),),
            ).fetchall()

        top_risks = [
            {
                "ip_address": row["ip_address"],
                "threat_score": row["threat_score"],
                "risk_level": row["risk_level"],
                "abuse_confidence": row["abuse_confidence"],
                "last_seen": datetime.fromisoformat(row["analyzed_at"]).isoformat(),
                "occurrence_count": row["occurrence_count"],
            }
            for row in top_risks_rows
        ]

        risk_counts = {row["risk_level"]: row["count"] for row in risk_counts_rows}
        volume = [
            {"bucket": row["bucket"], "count": row["count"]}
            for row in sorted(volume_rows, key=lambda r: r["bucket"])
        ]

        category_counts: Dict[str, int] = {}
        for row in category_rows:
            cats = json.loads(row["categories"]) if row["categories"] else []
            for cat in cats:
                category_counts[cat] = category_counts.get(cat, 0) + 1

        metrics = {
            "total_reports": total_reports,
            "unique_ips": distinct_ips,
            "last_analysis_at": last_row["analyzed_at"] if last_row else None,
        }

        return {
            "top_risks": top_risks,
            "risk_counts": risk_counts,
            "category_counts": category_counts,
            "report_volume": volume,
            "metrics": metrics,
        }
