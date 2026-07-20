"""
db.py - SQLite хранилище истории, профилей и сводок запусков
"""

import json
import sqlite3
import logging
from functools import lru_cache
from typing import List, Dict, Any, Optional, Tuple

try:
    import msgpack
    import zstandard as zstd
    _HAS_COMPRESSION = True
except ImportError:
    _HAS_COMPRESSION = False

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  Сжатие / распаковка
# --------------------------------------------------------------------------- #

def _compress(data: Any) -> bytes:
    """Сжимает данные (msgpack + zstd)."""
    if not _HAS_COMPRESSION:
        return json.dumps(data, ensure_ascii=False).encode('utf-8')
    try:
        packed = msgpack.packb(data, use_bin_type=True)
        return zstd.ZstdCompressor().compress(packed)
    except Exception:
        return json.dumps(data, ensure_ascii=False).encode('utf-8')


def _decompress(data: bytes) -> Any:
    """
    Распаковка БЕЗ lru_cache (ранее кеш возвращал разделяемый изменяемый объект,
    мутация которого ломала кеш). Каждый вызов возвращает свежий объект.
    """
    if not data:
        return None
    if not _HAS_COMPRESSION:
        try:
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None
    try:
        return msgpack.unpackb(zstd.ZstdDecompressor().decompress(data), raw=False)
    except Exception:
        try:
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None


class HistoryDB:
    """SQLite хранилище истории, профилей и сводок (синглтон)."""

    _instance = None

    def __new__(cls, db_path: str = 'configs/history.db'):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: str = 'configs/history.db'):
        if self._initialized:
            return
        self.db_path = db_path
        self._init_db()
        self._initialized = True

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Создаёт таблицы и применяет миграции."""
        conn = self._get_connection()
        try:
            with conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT,
                        channel_url TEXT,
                        total_configs INTEGER DEFAULT 0,
                        success INTEGER DEFAULT 0,
                        avg_latency REAL DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS channels (
                        channel_url TEXT PRIMARY KEY,
                        success_rate REAL DEFAULT 0,
                        total_configs INTEGER DEFAULT 0,
                        enabled INTEGER DEFAULT 1,
                        last_run TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS profiles (
                        fingerprint TEXT PRIMARY KEY,
                        data BLOB,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        total_raw INTEGER DEFAULT 0,
                        total_valid INTEGER DEFAULT 0,
                        total_final INTEGER DEFAULT 0,
                        avg_score REAL DEFAULT 0,
                        p50_latency REAL DEFAULT 0,
                        p95_latency REAL DEFAULT 0,
                        p99_latency REAL DEFAULT 0,
                        success_rate REAL DEFAULT 0,
                        protocols TEXT,
                        geo_distribution TEXT,
                        anomalies TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_history_channel ON history(channel_url);
                    CREATE INDEX IF NOT EXISTS idx_history_run ON history(run_id);
                    CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp);
                """)

                # [CHANGE] Миграция: добавляем колонку enabled, если БД создана
                # старой версией (из кеша) и колонки ещё нет.
                try:
                    conn.execute("ALTER TABLE channels ADD COLUMN enabled INTEGER DEFAULT 1")
                except sqlite3.OperationalError:
                    pass  # колонка уже существует
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  History
    # ------------------------------------------------------------------ #

    def add_history(self, run_id: str, channel_url: str, total_configs: int,
                    success: int, avg_latency: float = 0.0):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO history (run_id, channel_url, total_configs, success, avg_latency) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (run_id, channel_url, total_configs, success, avg_latency)
                )
        finally:
            conn.close()

    def get_channel_stats(self, channel_url: str, limit: int = 100) -> List[Dict]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT total_configs, success, avg_latency, created_at "
                "FROM history WHERE channel_url = ? ORDER BY created_at DESC LIMIT ?",
                (channel_url, limit)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  Channels
    # ------------------------------------------------------------------ #

    def get_channel(self, channel_url: str) -> Optional[Dict]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM channels WHERE channel_url = ?", (channel_url,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def update_channel(self, channel_url: str, **kwargs):
        conn = self._get_connection()
        try:
            with conn:
                existing = conn.execute(
                    "SELECT 1 FROM channels WHERE channel_url = ?", (channel_url,)
                ).fetchone()
                if existing:
                    sets = ', '.join(f"{k} = ?" for k in kwargs)
                    vals = list(kwargs.values()) + [channel_url]
                    conn.execute(
                        f"UPDATE channels SET {sets}, updated_at = CURRENT_TIMESTAMP "
                        f"WHERE channel_url = ?", vals
                    )
                else:
                    cols = ['channel_url'] + list(kwargs.keys())
                    placeholders = ', '.join('?' * len(cols))
                    vals = [channel_url] + list(kwargs.values())
                    conn.execute(
                        f"INSERT INTO channels ({', '.join(cols)}) VALUES ({placeholders})",
                        vals
                    )
        finally:
            conn.close()

    # [CHANGE] управление активностью каналов
    def set_channel_enabled(self, channel_url: str, enabled: bool):
        self.update_channel(channel_url, enabled=1 if enabled else 0)

    def get_inactive_channels(self) -> List[str]:
        """Возвращает URL каналов с enabled = 0."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT channel_url FROM channels WHERE enabled = 0"
            ).fetchall()
            return [r['channel_url'] for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  Profiles (одиночные)
    # ------------------------------------------------------------------ #

    def get_profile(self, fingerprint: str) -> Dict:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT data FROM profiles WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return (_decompress(row['data']) or {}) if row else {}
        finally:
            conn.close()

    def update_profile(self, fingerprint: str, data: Dict):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO profiles (fingerprint, data) VALUES (?, ?) "
                    "ON CONFLICT(fingerprint) DO UPDATE SET data = excluded.data, "
                    "updated_at = CURRENT_TIMESTAMP",
                    (fingerprint, _compress(data))
                )
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  Profiles (батчинг) — устраняет N+1 запросов
    # ------------------------------------------------------------------ #

    def get_profiles_batch(self, fingerprints: List[str]) -> Dict[str, Dict]:
        if not fingerprints:
            return {}
        conn = self._get_connection()
        result: Dict[str, Dict] = {}
        try:
            for i in range(0, len(fingerprints), 900):
                chunk = fingerprints[i:i + 900]
                placeholders = ','.join('?' * len(chunk))
                rows = conn.execute(
                    f"SELECT fingerprint, data FROM profiles "
                    f"WHERE fingerprint IN ({placeholders})", chunk
                ).fetchall()
                for row in rows:
                    result[row['fingerprint']] = _decompress(row['data']) or {}
            return result
        finally:
            conn.close()

    def update_profiles_batch(self, updates: List[Tuple[str, Dict]]):
        if not updates:
            return
        conn = self._get_connection()
        try:
            rows = [(fp, _compress(data)) for fp, data in updates]
            with conn:
                conn.executemany(
                    "INSERT INTO profiles (fingerprint, data) VALUES (?, ?) "
                    "ON CONFLICT(fingerprint) DO UPDATE SET data = excluded.data, "
                    "updated_at = CURRENT_TIMESTAMP",
                    rows
                )
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  [CHANGE] Сводки запусков (таблица runs)
    # ------------------------------------------------------------------ #

    def add_run_summary(self, run_id: str, total_raw: int = 0, total_valid: int = 0,
                        total_final: int = 0, avg_score: float = 0.0,
                        p50_latency: float = 0.0, p95_latency: float = 0.0,
                        p99_latency: float = 0.0, success_rate: float = 0.0,
                        protocols: Optional[Dict] = None,
                        geo_distribution: Optional[Dict] = None,
                        anomalies: Optional[List] = None):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO runs (run_id, total_raw, total_valid, total_final, "
                    "avg_score, p50_latency, p95_latency, p99_latency, success_rate, "
                    "protocols, geo_distribution, anomalies) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, total_raw, total_valid, total_final, avg_score,
                     p50_latency, p95_latency, p99_latency, success_rate,
                     json.dumps(protocols or {}),
                     json.dumps(geo_distribution or {}),
                     json.dumps(anomalies or []))
                )
        finally:
            conn.close()

    def get_latest_run_summary(self) -> Optional[Dict]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM runs ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
#  Ленивая инициализация синглтона (без побочных эффектов при импорте)
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=1)
def get_db(db_path: str = 'configs/history.db') -> HistoryDB:
    """Ленивая фабрика единственного экземпляра БД."""
    return HistoryDB(db_path)
