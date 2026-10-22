"""Offline GeoIP/ASN enrichment for SSHintel telemetry.

Attach country and ASN metadata to source IPs using a local database.
Opt-in: if no database is configured, enrichment is a silent no-op.
Never blocks event writes.

Supported database formats:
- MaxMind DB (.mmdb) via the optional ``maxminddb`` package
- Simple CSV with header: ip_start,ip_end,country,asn
"""

from __future__ import annotations

import csv
import socket
import struct
from pathlib import Path
from typing import Any


class Enricher:
    """Resolve source IPs to country and ASN using a local database.

    All lookup errors are swallowed; an unavailable enricher returns {}.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else None
        self._reader: Any = None
        self._csv_rows: list[tuple[int, int, str, str]] = []
        self._enabled = False

        if self.db_path is None or not self.db_path.exists():
            return

        suffix = self.db_path.suffix.lower()
        if suffix == ".mmdb":
            self._try_maxmind()
        elif suffix == ".csv":
            self._try_csv()
        else:
            # Unknown extension: try MaxMind first, then CSV.
            self._try_maxmind()
            if not self._enabled:
                self._try_csv()

    def _try_maxmind(self) -> None:
        try:
            import maxminddb  # type: ignore[import-not-found]
        except ImportError:
            return
        try:
            self._reader = maxminddb.open_reader(str(self.db_path))
            self._enabled = True
        except Exception:
            self._reader = None

    def _try_csv(self) -> None:
        try:
            with self.db_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    start = int(row["ip_start"])
                    end = int(row["ip_end"])
                    country = (row.get("country") or "").strip()
                    asn = (row.get("asn") or "").strip()
                    self._csv_rows.append((start, end, country, asn))
            self._csv_rows.sort(key=lambda r: r[0])
            self._enabled = True
        except Exception:
            self._csv_rows = []

    def enrich(self, ip: str) -> dict[str, str]:
        """Return ``{"country": ..., "asn": ...}`` for ``ip``, or ``{}``."""
        if not self._enabled:
            return {}
        try:
            socket.inet_aton(ip)  # validate
        except OSError:
            return {}

        if self._reader is not None:
            return self._enrich_maxmind(ip)
        return self._enrich_csv(ip)

    def _enrich_maxmind(self, ip: str) -> dict[str, str]:
        try:
            data = self._reader.get(ip) or {}
        except Exception:
            return {}
        result: dict[str, str] = {}
        country = (data.get("country", {}) or {}).get("iso_code") or ""
        if country:
            result["country"] = country
        asn_data = data.get("asn", {}) or {}
        asn_num = asn_data.get("autonomous_system_number")
        if asn_num:
            result["asn"] = f"AS{asn_num}"
        return result

    def _enrich_csv(self, ip: str) -> dict[str, str]:
        import bisect

        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        starts = [r[0] for r in self._csv_rows]
        idx = bisect.bisect_right(starts, ip_int) - 1
        if idx < 0:
            return {}
        start, end, country, asn = self._csv_rows[idx]
        if ip_int > end:
            return {}
        result: dict[str, str] = {}
        if country:
            result["country"] = country
        if asn:
            result["asn"] = asn
        return result

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass