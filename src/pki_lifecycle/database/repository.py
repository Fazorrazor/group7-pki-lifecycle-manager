"""
Parameterized Data Access Layer for PKI and Certificate Inventory.
Responsible: Peter Myles Etroo (Task 2: Week 2 Input-Handling Kit)

SECURITY MANDATE:
- All queries MUST use parameterized inputs (%s or ? placeholders).
- NEVER use string formatting, f-strings, or string concatenation to build SQL statements.
- Prevents CWE-89 (SQL Injection) as verified by Semgrep rules.
"""

from typing import Any, Dict, List, Optional
import sqlite3


class CertificateRepository:
    """
    Data-access repository managing endpoints, certificates, and scan results.
    Strictly uses parameterized queries for every database operation.
    """

    def __init__(self, connection: Any = None):
        """
        Accepts an active DB-API 2.0 connection or creates an in-memory SQLite store by default
        for isolated, secure unit testing.
        """
        if connection is None:
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._init_schema()
        else:
            self.conn = connection

    def _init_schema(self) -> None:
        """Initialize database schema with strict integrity constraints."""
        cursor = self.conn.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                environment TEXT NOT NULL DEFAULT 'lab',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (hostname, port)
            );

            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
                common_name TEXT NOT NULL,
                issuer TEXT NOT NULL,
                sans TEXT,
                key_type TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                valid_from TIMESTAMP NOT NULL,
                valid_to TIMESTAMP NOT NULL,
                is_revoked BOOLEAN DEFAULT 0,
                revocation_reason TEXT,
                chain_complete BOOLEAN DEFAULT 1,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER NOT NULL,
                certificate_id INTEGER,
                status TEXT NOT NULL,
                error_message TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
                FOREIGN KEY (certificate_id) REFERENCES certificates(id)
            );
            """
        )
        self.conn.commit()

    def add_endpoint(
        self, hostname: str, port: int, service_name: str, environment: str = "lab"
    ) -> int:
        """
        Adds a new endpoint using strictly parameterized query.
        """
        sql = """
            INSERT INTO endpoints (hostname, port, service_name, environment)
            VALUES (?, ?, ?, ?)
        """
        cursor = self.conn.cursor()
        # Parameterized execution protects against SQL Injection payloads in hostname/service_name
        cursor.execute(sql, (hostname, port, service_name, environment))
        self.conn.commit()
        return cursor.lastrowid

    def get_endpoint_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves endpoint details by hostname using parameterized lookup.
        """
        sql = "SELECT id, hostname, port, service_name, environment FROM endpoints WHERE hostname = ?"
        cursor = self.conn.cursor()
        cursor.execute(sql, (hostname,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)

    def search_endpoints_by_service(self, service_pattern: str) -> List[Dict[str, Any]]:
        """
        Safe parameterized LIKE query for service searching.
        Notice: the wildcard % is passed in the parameter tuple, NOT concatenated into the SQL!
        """
        sql = "SELECT id, hostname, port, service_name, environment FROM endpoints WHERE service_name LIKE ?"
        cursor = self.conn.cursor()
        cursor.execute(sql, (f"%{service_pattern}%",))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def record_certificate(
        self,
        serial_number: str,
        common_name: str,
        issuer: str,
        sans: str,
        key_type: str,
        key_size: int,
        valid_from: str,
        valid_to: str,
        chain_complete: bool = True,
    ) -> int:
        """
        Inserts or updates a certificate record using parameterized execution.
        """
        sql = """
            INSERT INTO certificates (
                serial_number, common_name, issuer, sans, key_type, key_size,
                valid_from, valid_to, chain_complete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(serial_number) DO UPDATE SET
                common_name = excluded.common_name,
                issuer = excluded.issuer,
                sans = excluded.sans,
                valid_to = excluded.valid_to,
                chain_complete = excluded.chain_complete,
                last_scanned = CURRENT_TIMESTAMP
        """
        cursor = self.conn.cursor()
        cursor.execute(
            sql,
            (
                serial_number,
                common_name,
                issuer,
                sans,
                key_type,
                key_size,
                valid_from,
                valid_to,
                int(chain_complete),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def revoke_certificate(self, serial_number: str, reason: str) -> bool:
        """
        Updates certificate revocation status using parameterized query.
        """
        sql = "UPDATE certificates SET is_revoked = 1, revocation_reason = ? WHERE serial_number = ?"
        cursor = self.conn.cursor()
        cursor.execute(sql, (reason, serial_number))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_expiring_certificates(self, days_threshold: int) -> List[Dict[str, Any]]:
        """
        Safe parameterized query finding certificates expiring within a specified threshold.
        """
        sql = """
            SELECT serial_number, common_name, issuer, valid_to, is_revoked
            FROM certificates
            WHERE is_revoked = 0
            AND valid_to <= datetime('now', ? || ' days')
        """
        cursor = self.conn.cursor()
        cursor.execute(sql, (str(days_threshold),))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def get_all_certificates(self) -> List[Dict[str, Any]]:
        """Retrieves all certificate records from inventory."""
        sql = "SELECT * FROM certificates ORDER BY valid_to ASC"
        cursor = self.conn.cursor()
        cursor.execute(sql)
        return [dict(r) for r in cursor.fetchall()]

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Retrieves all registered endpoints."""
        sql = "SELECT * FROM endpoints ORDER BY id ASC"
        cursor = self.conn.cursor()
        cursor.execute(sql)
        return [dict(r) for r in cursor.fetchall()]

    def get_certificate_by_serial(self, serial_number: str) -> Optional[Dict[str, Any]]:
        """Retrieves certificate record by serial number."""
        sql = "SELECT * FROM certificates WHERE serial_number = ?"
        cursor = self.conn.cursor()
        cursor.execute(sql, (serial_number,))
        row = cursor.fetchone()
        return dict(row) if row else None

