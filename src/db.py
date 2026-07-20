"""
Модуль для работы с SQLite-базой данных истории.
Добавлена таблица model_versions для отслеживания метрик обученных моделей.
"""

import sqlite3
import json
import zlib
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from functools import lru_cache
import time

logger = logging.getLogger(__name__)

DB_PATH = "configs/history.db"
COMPRESS_LEVEL = 6
SCHEMA_VERSION = 4  # увеличена для новой таблицы


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


class HistoryDB:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            cursor = conn.cursor()

            # Проверка версии схемы
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
            if cursor.fetchone():
                cursor.execute("SELECT value FROM metadata WHERE key='schema_version'")
                row = cursor.fetchone()
                if row:
                    version = int(row[0]) if row[0] else 0
                    if version < SCHEMA_VERSION:
                        logger.info(f"Upgrading schema from version {version} to {SCHEMA_VERSION}")
                        self._upgrade_schema(conn, version)

            # Таблицы
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
            # Новая таблица для версий моделей
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

            # Если метаданных нет, добавляем версию
            cursor.execute("SELECT value FROM metadata WHERE key='schema_version'")
            if not cursor.fetchone():
                cursor.execute("INSERT INTO metadata (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            conn.commit()
            logger.info(f"SQLite history database initialized (schema version {SCHEMA_VERSION})")

    def _upgrade_schema(self, conn, old_version: int):
        cursor = conn.cursor()
        if old_version < 1:
            pass
        if old_version < 2:
            pass
        if old_version < 3:
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
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_profile ON probe_history(profile_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_timestamp ON probe_history(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_success ON probe_history(success)")
        if old_version < 4:
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
            cursor.execute("UPDATE metadata SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))
            conn.commit()
            logger.info(f"Schema upgraded to version {SCHEMA_VERSION}")

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ... (все остальные методы остаются без изменений, кроме добавления новых)
    def add_run(self, stats: Dict) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO runs (
                    timestamp, total_raw, total_valid, total_final,
                    avg_score, p50_latency, p95_latency, p99_latency,
                    success_rate, protocols, geo_distribution, anomalies
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                stats.get('timestamp', datetime.now().isoformat()),
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
            conn.commit()
            return cursor.lastrowid

    def get_recent_runs(self, limit: int = 10) -> List[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM runs ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocols'] = _decompress(row['protocols']) or {}
                d['geo_distribution'] = _decompress(row['geo_distribution']) or {}
                d['anomalies'] = _decompress(row['anomalies']) or []
                result.append(d)
            return result

    def get_last_run(self) -> Optional[Dict]:
        runs = self.get_recent_runs(1)
        return runs[0] if runs else None

    def update_channel(self, url: str, metrics: Dict, enabled: bool = True):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO channels (url, enabled, metrics, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (url, 1 if enabled else 0, _compress(metrics), datetime.now().isoformat()))
            conn.commit()

    def get_channel(self, url: str) -> Optional[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channels WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d['metrics'] = _decompress(row['metrics']) or {}
                return d
            return None

    def get_all_channels(self) -> List[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channels')
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['metrics'] = _decompress(row['metrics']) or {}
                result.append(d)
            return result

    def update_profile(self, key: str, profile_data: Dict):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO profiles (
                    key, server, protocol, first_seen, last_seen,
                    success_count, fail_count, latencies, timestamps,
                    is_active, stability, lifetime, overall_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key,
                profile_data.get('server', ''),
                profile_data.get('protocol', ''),
                profile_data.get('first_seen', datetime.now().isoformat()),
                profile_data.get('last_seen', datetime.now().isoformat()),
                profile_data.get('success_count', 0),
                profile_data.get('fail_count', 0),
                _compress(profile_data.get('latencies', [])),
                _compress(profile_data.get('timestamps', [])),
                1 if profile_data.get('is_active', True) else 0,
                profile_data.get('stability', 0.0),
                profile_data.get('lifetime', 0.0),
                profile_data.get('overall_score', 0.0)
            ))
            conn.commit()

    def update_profiles_batch(self, profiles: List[Dict]):
        if not profiles:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for profile_data in profiles:
                cursor.execute('''
                    INSERT OR REPLACE INTO profiles (
                        key, server, protocol, first_seen, last_seen,
                        success_count, fail_count, latencies, timestamps,
                        is_active, stability, lifetime, overall_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    profile_data.get('key', ''),
                    profile_data.get('server', ''),
                    profile_data.get('protocol', ''),
                    profile_data.get('first_seen', datetime.now().isoformat()),
                    profile_data.get('last_seen', datetime.now().isoformat()),
                    profile_data.get('success_count', 0),
                    profile_data.get('fail_count', 0),
                    _compress(profile_data.get('latencies', [])),
                    _compress(profile_data.get('timestamps', [])),
                    1 if profile_data.get('is_active', True) else 0,
                    profile_data.get('stability', 0.0),
                    profile_data.get('lifetime', 0.0),
                    profile_data.get('overall_score', 0.0)
                ))
            conn.commit()

    def get_profile(self, key: str) -> Optional[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profiles WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['is_active'] = bool(row['is_active'])
                return d
            return None

    def get_all_profiles(self) -> List[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profiles')
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['is_active'] = bool(row['is_active'])
                result.append(d)
            return result

    def clean_old_profiles(self, days: int = 7):
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM profiles WHERE last_seen < ?", (cutoff,))
            conn.commit()
            logger.info(f"Cleaned profiles older than {days} days")

    def get_metadata(self, key: str, default: Any = None) -> Any:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                try:
                    return json.loads(row['value'])
                except:
                    return row['value']
            return default

    def set_metadata(self, key: str, value: Any):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)', (key, json.dumps(value)))
            conn.commit()

    def add_channel_history(self, url: str, run_id: int, metrics: Dict):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
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
                datetime.now().isoformat()
            ))
            conn.commit()

    def get_channel_history(self, url: str, limit: int = 10) -> List[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channel_history WHERE url = ? ORDER BY timestamp DESC LIMIT ?', (url, limit))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocol_counts'] = _decompress(row['protocol_counts']) or {}
                result.append(d)
            return result

    def get_channel_history_scores(self, url: str, days: int = 7) -> List[Dict]:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT timestamp, overall_score FROM channel_history WHERE url = ? AND timestamp >= ? ORDER BY timestamp ASC', (url, cutoff))
            rows = cursor.fetchall()
            return [{'timestamp': row['timestamp'], 'score': row['overall_score']} for row in rows]

    def get_channel_long_term_score(self, url: str, days: int = 7) -> Optional[float]:
        scores = self.get_channel_history_scores(url, days)
        valid_scores = [s['score'] for s in scores if s['score'] > 0]
        if not valid_scores:
            return None
        return sum(valid_scores) / len(valid_scores)

    # ========== Новые методы для модели ==========

    def save_model_version(self, version: str, rmse: float, mae: float, trained_on: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO model_versions (version, rmse, mae, trained_on, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (version, rmse, mae, trained_on, datetime.now().isoformat()))
            conn.commit()
            logger.info(f"Model version saved: {version} (RMSE={rmse:.2f}, MAE={mae:.2f})")

    def get_best_model(self) -> Optional[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM model_versions ORDER BY rmse ASC LIMIT 1')
            row = cursor.fetchone()
            return dict(row) if row else None

    # ========== Существующие методы для probe/features ==========

    def update_profile_features(self, features: Dict):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            columns = ', '.join(features.keys())
            placeholders = ', '.join(['?'] * len(features))
            cursor.execute(f'''
                INSERT OR REPLACE INTO profile_features ({columns})
                VALUES ({placeholders})
            ''', list(features.values()))
            conn.commit()

    def get_profile_features(self, profile_key: str) -> Optional[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profile_features WHERE profile_key = ?', (profile_key,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def add_probe_history(self, probe_data: Dict):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO probe_history (
                    profile_key, timestamp, success, latency,
                    tls_handshake_latency, http_first_byte, http_total,
                    status_code, error_type, protocol, transport,
                    sni_used, host_used, path_used,
                    attempt_number, total_attempts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                probe_data.get('profile_key', ''),
                probe_data.get('timestamp', datetime.now().isoformat()),
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
            conn.commit()

    def get_probe_history(self, profile_key: str, since_hours: int = 24) -> List[Dict]:
        cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM probe_history
                WHERE profile_key = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (profile_key, cutoff))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_recent_probes(self, since_hours: int = 24) -> List[Dict]:
        cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM probe_history
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (cutoff,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

_db = None

def get_db() -> HistoryDB:
    global _db
    if _db is None:
        _db = HistoryDB()
        _db.clean_old_profiles(days=7)
    return _db
