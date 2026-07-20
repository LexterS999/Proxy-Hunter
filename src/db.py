"""
Модуль для работы с SQLite-базой данных истории.
Использует aiosqlite для асинхронного пула соединений.
"""

import sqlite3
import json
import zlib
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from contextlib import asynccontextmanager
from functools import lru_cache
import asyncio
import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = "configs/history.db"
COMPRESS_LEVEL = 6
SCHEMA_VERSION = 5

# Пул соединений
_connection_pool: Optional[aiosqlite.Connection] = None
_pool_lock = asyncio.Lock()


def _compress(data: Any) -> bytes:
    if data is None:
        return b''
    try:
        return zlib.compress(json.dumps(data).encode('utf-8'), level=COMPRESS_LEVEL)
    except Exception:
        return b''


@lru_cache(maxsize=8192)
def _decompress_cached(blob: bytes) -> Any:
    if blob is None or not blob:
        return None
    try:
        return json.loads(zlib.decompress(blob).decode('utf-8'))
    except Exception:
        return None


def _decompress(blob: bytes) -> Any:
    return _decompress_cached(blob)


def _now_utc() -> str:
    """Возвращает текущее время в UTC в ISO-формате."""
    return datetime.now(timezone.utc).isoformat()


class HistoryDB:
    """Асинхронная работа с БД через пул соединений."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_sync()
        return cls._instance

    def _init_sync(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        # Синхронная инициализация схемы
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            cursor = conn.cursor()
            self._init_schema(cursor)
            conn.commit()
        self._pool: Optional[aiosqlite.Connection] = None

    def _init_schema(self, cursor):
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")

        # Проверка версии схемы
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
        if cursor.fetchone():
            cursor.execute("SELECT value FROM metadata WHERE key='schema_version'")
            row = cursor.fetchone()
            if row:
                version = int(row[0]) if row[0] else 0
                if version < SCHEMA_VERSION:
                    logger.info(f"Upgrading schema from version {version} to {SCHEMA_VERSION}")
                    self._upgrade_schema(cursor, version)

        # Основные таблицы
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_raw INTEGER,
                total_valid INTEGER,
                total_final INTEGER,
                avg_score REAL,
                p50_latency REAL,
                p95_latency REAL,
                p99_latency REAL,
                success_rate REAL,
                protocols BLOB,
                geo_distribution BLOB,
                anomalies BLOB
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                url TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                metrics BLOB,
                last_updated TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                key TEXT PRIMARY KEY,
                server TEXT,
                protocol TEXT,
                first_seen TEXT,
                last_seen TEXT,
                success_count INTEGER DEFAULT 0,
                fail_count INTEGER DEFAULT 0,
                latencies BLOB,
                timestamps BLOB,
                is_active INTEGER DEFAULT 1,
                stability REAL,
                lifetime REAL,
                overall_score REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS channel_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                run_id INTEGER,
                total_configs INTEGER,
                valid_configs INTEGER,
                unique_configs INTEGER,
                avg_response_time REAL,
                overall_score REAL,
                protocol_counts BLOB,
                timestamp TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profile_features (
                profile_key TEXT PRIMARY KEY,
                protocol TEXT,
                transport TEXT,
                has_sni INTEGER,
                has_host INTEGER,
                has_path INTEGER,
                has_pbk INTEGER,
                has_flow INTEGER,
                is_reality INTEGER,
                alter_id INTEGER,
                ss_method TEXT,
                sni_count INTEGER,
                host_count INTEGER,
                path_count INTEGER,
                config_length INTEGER,
                count_1h INTEGER,
                count_6h INTEGER,
                count_24h INTEGER,
                count_7d INTEGER,
                success_1h INTEGER,
                success_6h INTEGER,
                success_24h INTEGER,
                success_7d INTEGER,
                avg_latency_1h REAL,
                avg_latency_6h REAL,
                avg_latency_24h REAL,
                avg_latency_7d REAL,
                p90_latency_24h REAL,
                p99_latency_24h REAL,
                latency_std_24h REAL,
                latency_cv_24h REAL,
                latency_trend_24h REAL,
                check_interval_avg REAL,
                same_ip_count INTEGER,
                same_ip_success_rate REAL,
                same_sni_count INTEGER,
                last_updated TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS probe_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_key TEXT,
                timestamp TEXT,
                success INTEGER,
                latency REAL,
                tls_handshake_latency REAL,
                http_first_byte REAL,
                http_total REAL,
                status_code INTEGER,
                error_type TEXT,
                protocol TEXT,
                transport TEXT,
                sni_used TEXT,
                host_used TEXT,
                path_used TEXT,
                attempt_number INTEGER,
                total_attempts INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT,
                rmse REAL,
                mae REAL,
                trained_on TEXT,
                created_at TEXT
            )
        ''')
        # Новая таблица для кеша парсинга
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS parsed_cache (
                cache_key TEXT PRIMARY KEY,
                parsed_data BLOB,
                created_at TEXT,
                updated_at TEXT
            )
        ''')

        # Индексы
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_url ON channel_history(url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_timestamp ON channel_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_run_id ON channel_history(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_server ON profiles(server)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON profiles(last_seen)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_profile ON probe_history(profile_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_timestamp ON probe_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_success ON probe_history(success)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_cache_key ON parsed_cache(cache_key)")

        if not cursor.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone():
            cursor.execute("INSERT INTO metadata (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    def _upgrade_schema(self, cursor, old_version: int):
        if old_version < 5:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS parsed_cache (
                    cache_key TEXT PRIMARY KEY,
                    parsed_data BLOB,
                    created_at TEXT,
                    updated_at TEXT
                )
            ''')
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parsed_cache_key ON parsed_cache(cache_key)")
            cursor.execute("UPDATE metadata SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))
            logger.info(f"Schema upgraded to version {SCHEMA_VERSION}")

    async def _get_connection(self) -> aiosqlite.Connection:
        """Возвращает соединение из пула."""
        global _connection_pool
        async with _pool_lock:
            if _connection_pool is None or await _connection_pool.closed():
                _connection_pool = await aiosqlite.connect(DB_PATH)
                await _connection_pool.execute("PRAGMA journal_mode=WAL")
                await _connection_pool.execute("PRAGMA synchronous=NORMAL")
                logger.info("Created new aiosqlite connection pool")
            return _connection_pool

    @asynccontextmanager
    async def _transaction(self):
        """Контекстный менеджер для транзакций."""
        conn = await self._get_connection()
        async with conn:
            yield conn

    async def add_run(self, stats: Dict) -> int:
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT INTO runs (
                    timestamp, total_raw, total_valid, total_final,
                    avg_score, p50_latency, p95_latency, p99_latency,
                    success_rate, protocols, geo_distribution, anomalies
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                stats.get('timestamp', _now_utc()),
                stats.get('total_raw', 0),
                stats.get('total_valid', 0),
                stats.get('total_final', 0),
                stats.get('avg_score', 0.0),
                stats.get('p50_latency', 0.0),
                stats.get('p95_latency', 0.0),
                stats.get('p99_latency', 0.0),
                stats.get('success_rate', 0.0),
                _compress(stats.get('protocols', {})),
                _compress(stats.get('geo_distribution', {})),
                _compress(stats.get('anomalies', []))
            ))
            await conn.commit()
            return cursor.lastrowid

    async def get_recent_runs(self, limit: int = 10) -> List[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM runs ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = await cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocols'] = _decompress(row['protocols']) or {}
                d['geo_distribution'] = _decompress(row['geo_distribution']) or {}
                d['anomalies'] = _decompress(row['anomalies']) or []
                result.append(d)
            return result

    async def get_last_run(self) -> Optional[Dict]:
        runs = await self.get_recent_runs(1)
        return runs[0] if runs else None

    async def update_channel(self, url: str, metrics: Dict, enabled: bool = True):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT OR REPLACE INTO channels (url, enabled, metrics, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (url, 1 if enabled else 0, _compress(metrics), _now_utc()))
            await conn.commit()

    async def get_channel(self, url: str) -> Optional[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM channels WHERE url = ?', (url,))
            row = await cursor.fetchone()
            if row:
                d = dict(row)
                d['metrics'] = _decompress(row['metrics']) or {}
                return d
            return None

    async def get_all_channels(self) -> List[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM channels')
            rows = await cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['metrics'] = _decompress(row['metrics']) or {}
                result.append(d)
            return result

    async def update_profile(self, key: str, profile_data: Dict):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT OR REPLACE INTO profiles (
                    key, server, protocol, first_seen, last_seen,
                    success_count, fail_count, latencies, timestamps,
                    is_active, stability, lifetime, overall_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key,
                profile_data.get('server', ''),
                profile_data.get('protocol', ''),
                profile_data.get('first_seen', _now_utc()),
                profile_data.get('last_seen', _now_utc()),
                profile_data.get('success_count', 0),
                profile_data.get('fail_count', 0),
                _compress(profile_data.get('latencies', [])),
                _compress(profile_data.get('timestamps', [])),
                1 if profile_data.get('is_active', True) else 0,
                profile_data.get('stability', 0.0),
                profile_data.get('lifetime', 0.0),
                profile_data.get('overall_score', 0.0)
            ))
            await conn.commit()

    async def update_profiles_batch(self, profiles: List[Dict]):
        if not profiles:
            return
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            for profile_data in profiles:
                await cursor.execute('''
                    INSERT OR REPLACE INTO profiles (
                        key, server, protocol, first_seen, last_seen,
                        success_count, fail_count, latencies, timestamps,
                        is_active, stability, lifetime, overall_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    profile_data.get('key', ''),
                    profile_data.get('server', ''),
                    profile_data.get('protocol', ''),
                    profile_data.get('first_seen', _now_utc()),
                    profile_data.get('last_seen', _now_utc()),
                    profile_data.get('success_count', 0),
                    profile_data.get('fail_count', 0),
                    _compress(profile_data.get('latencies', [])),
                    _compress(profile_data.get('timestamps', [])),
                    1 if profile_data.get('is_active', True) else 0,
                    profile_data.get('stability', 0.0),
                    profile_data.get('lifetime', 0.0),
                    profile_data.get('overall_score', 0.0)
                ))
            await conn.commit()

    async def get_profile(self, key: str) -> Optional[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM profiles WHERE key = ?', (key,))
            row = await cursor.fetchone()
            if row:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['is_active'] = bool(row['is_active'])
                return d
            return None

    async def get_all_profiles(self) -> List[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM profiles')
            rows = await cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['is_active'] = bool(row['is_active'])
                result.append(d)
            return result

    async def clean_old_profiles(self, days: int = 7):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute("DELETE FROM profiles WHERE last_seen < ?", (cutoff,))
            await conn.commit()
            logger.info(f"Cleaned profiles older than {days} days")

    async def get_metadata(self, key: str, default: Any = None) -> Any:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
            row = await cursor.fetchone()
            if row:
                try:
                    return json.loads(row['value'])
                except:
                    return row['value']
            return default

    async def set_metadata(self, key: str, value: Any):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)', (key, json.dumps(value)))
            await conn.commit()

    async def add_channel_history(self, url: str, run_id: int, metrics: Dict):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT INTO channel_history (
                    url, run_id, total_configs, valid_configs, unique_configs,
                    avg_response_time, overall_score, protocol_counts, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                url,
                run_id,
                metrics.get('total_configs', 0),
                metrics.get('valid_configs', 0),
                metrics.get('unique_configs', 0),
                metrics.get('avg_response_time', 0.0),
                metrics.get('overall_score', 0.0),
                _compress(metrics.get('protocol_counts', {})),
                _now_utc()
            ))
            await conn.commit()

    async def get_channel_history(self, url: str, limit: int = 10) -> List[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM channel_history WHERE url = ? ORDER BY timestamp DESC LIMIT ?', (url, limit))
            rows = await cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocol_counts'] = _decompress(row['protocol_counts']) or {}
                result.append(d)
            return result

    async def get_channel_history_scores(self, url: str, days: int = 7, limit: int = 100) -> List[Dict]:
        """Возвращает историю скоров канала за N дней с ограничением."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('''
                SELECT timestamp, overall_score FROM channel_history
                WHERE url = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                LIMIT ?
            ''', (url, cutoff, limit))
            rows = await cursor.fetchall()
            return [{'timestamp': row['timestamp'], 'score': row['overall_score']} for row in rows]

    async def get_channel_long_term_score(self, url: str, days: int = 7) -> Optional[float]:
        scores = await self.get_channel_history_scores(url, days)
        valid_scores = [s['score'] for s in scores if s['score'] > 0]
        if not valid_scores:
            return None
        return sum(valid_scores) / len(valid_scores)

    # ========== Кеш парсинга ==========

    async def get_parsed_cache(self, cache_key: str) -> Optional[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT parsed_data FROM parsed_cache WHERE cache_key = ?', (cache_key,))
            row = await cursor.fetchone()
            if row:
                return _decompress(row['parsed_data'])
            return None

    async def get_parsed_cache_batch(self, keys: List[str]) -> Dict[str, Dict]:
        """Пакетное получение кеша."""
        if not keys:
            return {}
        result = {}
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            placeholders = ','.join(['?'] * len(keys))
            await cursor.execute(f'SELECT cache_key, parsed_data FROM parsed_cache WHERE cache_key IN ({placeholders})', keys)
            rows = await cursor.fetchall()
            for row in rows:
                data = _decompress(row['parsed_data'])
                if data:
                    result[row['cache_key']] = data
            return result

    async def set_parsed_cache(self, cache_key: str, parsed_data: Dict):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT OR REPLACE INTO parsed_cache (cache_key, parsed_data, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (cache_key, _compress(parsed_data), _now_utc(), _now_utc()))
            await conn.commit()

    async def set_parsed_cache_batch(self, items: Dict[str, Dict]):
        """Пакетная запись в кеш парсинга."""
        if not items:
            return
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            for key, data in items.items():
                await cursor.execute('''
                    INSERT OR REPLACE INTO parsed_cache (cache_key, parsed_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                ''', (key, _compress(data), _now_utc(), _now_utc()))
            await conn.commit()

    # ========== Модели ==========

    async def save_model_version(self, version: str, rmse: float, mae: float, trained_on: str):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT INTO model_versions (version, rmse, mae, trained_on, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (version, rmse, mae, trained_on, _now_utc()))
            await conn.commit()
            logger.info(f"Model version saved: {version} (RMSE={rmse:.2f}, MAE={mae:.2f})")

    async def get_best_model(self) -> Optional[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM model_versions ORDER BY rmse ASC LIMIT 1')
            row = await cursor.fetchone()
            return dict(row) if row else None

    # ========== Признаки и зонды ==========

    async def update_profile_features(self, features: Dict):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            columns = ', '.join(features.keys())
            placeholders = ', '.join(['?'] * len(features))
            await cursor.execute(f'''
                INSERT OR REPLACE INTO profile_features ({columns})
                VALUES ({placeholders})
            ''', list(features.values()))
            await conn.commit()

    async def get_profile_features(self, profile_key: str) -> Optional[Dict]:
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('SELECT * FROM profile_features WHERE profile_key = ?', (profile_key,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def add_probe_history(self, probe_data: Dict):
        async with self._transaction() as conn:
            cursor = await conn.cursor()
            await cursor.execute('''
                INSERT INTO probe_history (
                    profile_key, timestamp, success, latency,
                    tls_handshake_latency, http_first_byte, http_total,
                    status_code, error_type, protocol, transport,
                    sni_used, host_used, path_used,
                    attempt_number, total_attempts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                probe_data.get('profile_key', ''),
                probe_data.get('timestamp', _now_utc()),
                1 if probe_data.get('success') else 0,
                probe_data.get('latency', 0),
                probe_data.get('tls_handshake', 0),
                probe_data.get('http_first_byte', 0),
                probe_data.get('http_total', 0),
                probe_data.get('status_code', 0),
                probe_data.get('error'),
                probe_data.get('protocol'),
                probe_data.get('transport'),
                probe_data.get('sni_used'),
                probe_data.get('host_used'),
                probe_data.get('path_used'),
                probe_data.get('attempt_number', 1),
                probe_data.get('total_attempts', 1)
            ))
            await conn.commit()

    async def get_probe_history(self, profile_key: str, since_hours: int = 24) -> List[Dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('''
                SELECT * FROM probe_history
                WHERE profile_key = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (profile_key, cutoff))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_recent_probes(self, since_hours: int = 24) -> List[Dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        async with self._get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute('''
                SELECT * FROM probe_history
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (cutoff,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def close(self):
        global _connection_pool
        if _connection_pool is not None:
            await _connection_pool.close()
            _connection_pool = None
            logger.info("Closed database connection pool")


_db = None


def get_db() -> HistoryDB:
    global _db
    if _db is None:
        _db = HistoryDB()
    return _db
