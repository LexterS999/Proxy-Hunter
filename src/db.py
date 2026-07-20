"""
db.py - SQLite хранилище истории и профилей
"""

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
        import json
        return json.dumps(data, ensure_ascii=False).encode('utf-8')
    try:
        packed = msgpack.packb(data, use_bin_type=True)
        return zstd.ZstdCompressor().compress(packed)
    except Exception:
        import json
        return json.dumps(data, ensure_ascii=False).encode('utf-8')


def _decompress(data: bytes) -> Any:
    """
    [CHANGE] Распаковка БЕЗ lru_cache.
    Ранее @lru_cache кэшировал большие blob'ы и возвращал тот же изменяемый
    объект (dict/list) — мутация результата ломала кеш. Теперь каждый вызов
    возвращает свежий объект.
    """
    if not data:
        return None
    if not _HAS_COMPRESSION:
        import json
        try:
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None
    try:
        return msgpack.unpackb(zstd.ZstdDecompressor().decompress(data), raw=False)
    except Exception:
        import json
        try:
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None


class HistoryDB:
    """SQLite хранилище истории запусков и профилей конфигов (синглтон)."""

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
        """Создаёт таблицы (если не существуют)."""
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
                        last_run TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS profiles (
                        fingerprint TEXT PRIMARY KEY,
                        data BLOB,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE INDEX IF NOT EXISTS idx_history_channel
                        ON history(channel_url);
                    CREATE INDEX IF NOT EXISTS idx_history_run
                        ON history(run_id);
                """)
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
        """Возвращает последние записи истории для канала."""
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
        """Создаёт или обновляет запись канала."""
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

    # ------------------------------------------------------------------ #
    #  Profiles (одиночные)
    # ------------------------------------------------------------------ #

    def get_profile(self, fingerprint: str) -> Dict:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT data FROM profiles WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if row:
                return _decompress(row['data']) or {}
            return {}
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
    #  [CHANGE] Profiles (батчинг) — устраняет N+1 запросов
    # ------------------------------------------------------------------ #

    def get_profiles_batch(self, fingerprints: List[str]) -> Dict[str, Dict]:
        """
        Пакетная загрузка профилей. SQLite ограничивает число параметров (~999),
        поэтому бьём на чанки по 900.
        """
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
        """
        Пакетная запись профилей в одной транзакции (executemany).
        updates: список (fingerprint, data).
        """
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


# --------------------------------------------------------------------------- #
#  [CHANGE] Ленивая инициализация синглтона.
#  Ранее в конце модуля было `_db = HistoryDB()`, что создавало БД при ЛЮБОМ
#  импорте db (побочный эффект). Теперь экземпляр создаётся только при вызове.
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=1)
def get_db(db_path: str = 'configs/history.db') -> HistoryDB:
    """Ленивая фабрика единственного экземпляра БД."""
    return HistoryDB(db_path)
