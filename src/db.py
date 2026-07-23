# ============================================================================
# Файл: src/db.py (обновлён с транзакциями, миграциями и автоматической очисткой)
# ============================================================================
#!/usr/bin/env python3

"""
Модуль для работы с SQLite-базой данных истории.
Хранит статистику запусков, каналов и профилей с компрессией.
Добавлены:
- Транзакции для массовых операций
- Автоматическая очистка старых данных
- Индексы для ускорения запросов
- Миграции схемы
- Ретрай-механизм через tenacity
"""

import sqlite3
import json
import zlib
import logging
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from contextlib import contextmanager
from collections import OrderedDict
from functools import wraps

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from user_settings import get_settings

logger = logging.getLogger(__name__)

# Получаем настройки
settings = get_settings()
DB_PATH = settings.database.db_path
COMPRESS_LEVEL = 6  # Уровень сжатия zlib


# ============================================================================
# РЕТРАЙ-МЕХАНИЗМ ДЛЯ ОПЕРАЦИЙ С БД
# ============================================================================

def retry_db(func):
    """Декоратор для ретраев операций с БД."""
    @wraps(func)
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, min=0.1, max=1.0),
        retry=retry_if_exception_type(sqlite3.OperationalError)
    )
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


# ============================================================================
# КЕШИРОВАНИЕ
# ============================================================================

class TTLCache:
    """Кеш с TTL-инвалидацией для распакованных blobs. Потокобезопасен."""

    def __init__(self, maxsize: int = 1024, ttl_seconds: float = 300.0):
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._cache: OrderedDict[bytes, Tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, blob: bytes) -> Optional[Any]:
        """Получает значение из кеша. Возвращает None если не найдено или устарело."""
        if blob is None or not blob:
            return None
        with self._lock:
            if blob in self._cache:
                timestamp, value = self._cache[blob]
                if time.time() - timestamp < self._ttl:
                    self._cache.move_to_end(blob)
                    return value
                else:
                    del self._cache[blob]
            return None

    def put(self, blob: bytes, value: Any) -> None:
        """Сохраняет значение в кеш."""
        if blob is None or not blob:
            return
        with self._lock:
            if blob in self._cache:
                self._cache.move_to_end(blob)
                self._cache[blob] = (time.time(), value)
            else:
                if len(self._cache) >= self._maxsize:
                    self._cache.popitem(last=False)
                self._cache[blob] = (time.time(), value)

    def invalidate(self) -> None:
        """Полная инвалидация кеша."""
        with self._lock:
            self._cache.clear()

    def invalidate_prefix(self, prefix: bytes) -> None:
        """Инвалидация записей по префиксу."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._cache[k]


# Глобальный TTL-кеш для распаковки
_decompress_cache = TTLCache(maxsize=1024, ttl_seconds=300.0)


def _compress(data: Any) -> bytes:
    """Сжимает JSON-данные в bytes."""
    if data is None:
        return b""
    try:
        return zlib.compress(json.dumps(data).encode("utf-8"), level=COMPRESS_LEVEL)
    except Exception:
        return b""


def _decompress_cached(blob: bytes) -> Any:
    """Распаковывает bytes в JSON-объект с TTL-кешированием."""
    if blob is None or not blob:
        return None
    cached = _decompress_cache.get(blob)
    if cached is not None:
        return cached
    try:
        result = json.loads(zlib.decompress(blob).decode("utf-8"))
        _decompress_cache.put(blob, result)
        return result
    except Exception:
        return None


def _decompress(blob: bytes) -> Any:
    """Обёртка для обратной совместимости."""
    return _decompress_cached(blob)


def invalidate_decompress_cache() -> None:
    """Очищает кеш распаковки."""
    _decompress_cache.invalidate()


# ============================================================================
# БАЗА ДАННЫХ
# ============================================================================

class HistoryDB:
    """Синглтон для доступа к SQLite базе истории с транзакциями и WAL."""

    _instance: Optional["HistoryDB"] = None

    def __new__(cls) -> "HistoryDB":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self) -> None:
        """Создаёт таблицы, индексы, включает WAL и авто-вакуум."""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA auto_vacuum = FULL")
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            # Таблица запусков (runs)
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

            # Таблица каналов (channels)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS channels (
                    url TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    metrics BLOB,
                    last_updated TEXT
                )
            ''')

            # Таблица профилей (profiles)
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
                    sni_history BLOB,
                    host_history BLOB,
                    is_active INTEGER DEFAULT 1,
                    stability REAL,
                    lifetime REAL,
                    overall_score REAL
                )
            ''')

            # Таблица метаданных
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')

            # Таблица истории каналов (channel_history)
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

            # Таблица карантина каналов
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS channel_grace (
                    url TEXT PRIMARY KEY,
                    grace_remaining INTEGER DEFAULT 0,
                    last_bad_run INTEGER,
                    last_updated TEXT,
                    FOREIGN KEY(last_bad_run) REFERENCES runs(id)
                )
            ''')

            # Таблица истории проверок (probe_history)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS probe_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_key TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    latency REAL DEFAULT 0,
                    tls_handshake_latency REAL DEFAULT 0,
                    http_first_byte REAL DEFAULT 0,
                    http_total REAL DEFAULT 0,
                    status_code INTEGER DEFAULT 0,
                    error_type TEXT,
                    protocol TEXT,
                    transport TEXT,
                    sni_used TEXT,
                    host_used TEXT,
                    path_used TEXT,
                    attempt_number INTEGER DEFAULT 1,
                    total_attempts INTEGER DEFAULT 1
                )
            ''')

            # Таблица фич профилей (profile_features)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS profile_features (
                    profile_key TEXT PRIMARY KEY,
                    server TEXT,
                    port INTEGER DEFAULT 0,
                    protocol TEXT,
                    transport TEXT,
                    sni TEXT,
                    host TEXT,
                    path TEXT,
                    has_sni INTEGER DEFAULT 0,
                    has_host INTEGER DEFAULT 0,
                    has_path INTEGER DEFAULT 0,
                    has_pbk INTEGER DEFAULT 0,
                    has_flow INTEGER DEFAULT 0,
                    is_reality INTEGER DEFAULT 0,
                    alter_id INTEGER DEFAULT 0,
                    ss_method TEXT,
                    config_length INTEGER DEFAULT 0,
                    sni_count INTEGER DEFAULT 0,
                    host_count INTEGER DEFAULT 0,
                    path_count INTEGER DEFAULT 0,
                    same_ip_count INTEGER DEFAULT 0,
                    same_ip_success_rate REAL DEFAULT 0,
                    same_sni_count INTEGER DEFAULT 0,
                    count_1h INTEGER DEFAULT 0,
                    success_1h INTEGER DEFAULT 0,
                    avg_latency_1h REAL DEFAULT 0,
                    count_6h INTEGER DEFAULT 0,
                    success_6h INTEGER DEFAULT 0,
                    avg_latency_6h REAL DEFAULT 0,
                    count_24h INTEGER DEFAULT 0,
                    success_24h INTEGER DEFAULT 0,
                    avg_latency_24h REAL DEFAULT 0,
                    p90_latency_24h REAL DEFAULT 0,
                    p99_latency_24h REAL DEFAULT 0,
                    latency_std_24h REAL DEFAULT 0,
                    latency_cv_24h REAL DEFAULT 0,
                    latency_trend_24h REAL DEFAULT 0,
                    check_interval_avg REAL DEFAULT 0,
                    count_7d INTEGER DEFAULT 0,
                    success_7d INTEGER DEFAULT 0,
                    avg_latency_7d REAL DEFAULT 0
                )
            ''')

            # Индексы для ускорения запросов
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_key ON profiles(key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_server ON profiles(server)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON profiles(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_history_profile_key ON probe_history(profile_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_history_profile_time ON probe_history(profile_key, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_history_sni_time ON probe_history(sni_used, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_probe_history_success_time ON probe_history(success, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_url ON channel_history(url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_timestamp ON channel_history(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_run_id ON channel_history(run_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_url_run ON channel_history(url, run_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profile_features_server ON profile_features(server)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profile_features_protocol ON profile_features(protocol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp)")

            # Миграции схемы
            self._ensure_schema_migrations(conn)

            conn.commit()
            logger.info("SQLite history database initialized with indexes, WAL, and auto_vacuum=FULL.")

    def _ensure_schema_migrations(self, conn) -> None:
        """Обеспечивает миграции схемы БД."""
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(profiles)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        # Добавляем отсутствующие колонки
        migrations = [
            ("sni_history", "ALTER TABLE profiles ADD COLUMN sni_history BLOB"),
            ("host_history", "ALTER TABLE profiles ADD COLUMN host_history BLOB"),
        ]
        for column, sql in migrations:
            if column not in existing_columns:
                try:
                    cursor.execute(sql)
                    logger.info(f"Applied migration: {sql}")
                except sqlite3.OperationalError as e:
                    logger.error(f"Failed to apply migration for {column}: {e}")

    @contextmanager
    def _get_connection(self):
        """Контекстный менеджер для получения соединения с БД."""
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @retry_db
    def cleanup_old_data(self, days: int = None) -> None:
        """Удаляет старые данные из БД (старше `days` дней)."""
        if days is None:
            days = settings.database.auto_cleanup_days
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                # Удаляем старые записи из probe_history
                cursor.execute("DELETE FROM probe_history WHERE timestamp < ?", (cutoff,))
                
                # Удаляем старые записи из channel_history
                cursor.execute("DELETE FROM channel_history WHERE timestamp < ?", (cutoff,))
                
                # Удаляем старые записи из runs (кроме последних MAX_HISTORY_RUNS)
                cursor.execute(
                    "DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY timestamp DESC LIMIT ?)",
                    (settings.database.max_history_runs,)
                )
                
                # Удаляем профили, которые не обновлялись давно
                cursor.execute("DELETE FROM profiles WHERE last_seen < ?", (cutoff,))
                
                # Удаляем неактивные каналы
                cursor.execute("DELETE FROM channels WHERE enabled = 0 AND last_updated < ?", (cutoff,))
                
                conn.commit()
                logger.info(f"Cleaned up data older than {days} days")
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to cleanup old data: {e}")
                raise

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С RUNS =====
    @retry_db
    def add_run(self, stats: Dict) -> int:
        """Добавляет запись о запуске."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
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
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to add run: {e}")
                raise

    @retry_db
    def get_recent_runs(self, limit: int = 10) -> List[Dict]:
        """Возвращает последние запуски."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM runs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocols'] = _decompress(row['protocols']) or {}
                d['geo_distribution'] = _decompress(row['geo_distribution']) or {}
                d['anomalies'] = _decompress(row['anomalies']) or []
                result.append(d)
            return result

    @retry_db
    def get_last_run(self) -> Optional[Dict]:
        """Возвращает последний запуск."""
        runs = self.get_recent_runs(1)
        return runs[0] if runs else None

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С КАНАЛАМИ =====
    @retry_db
    def update_channel(self, url: str, metrics: Dict, enabled: bool = True) -> None:
        """Обновляет информацию о канале."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO channels (url, enabled, metrics, last_updated)
                    VALUES (?, ?, ?, ?)
                ''', (
                    url,
                    1 if enabled else 0,
                    _compress(metrics),
                    datetime.now().isoformat()
                ))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to update channel {url}: {e}")
                raise
        invalidate_decompress_cache()

    @retry_db
    def get_channel(self, url: str) -> Optional[Dict]:
        """Возвращает информацию о канале."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channels WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d['metrics'] = _decompress(row['metrics']) or {}
                return d
            return None

    @retry_db
    def get_all_channels(self) -> List[Dict]:
        """Возвращает список всех каналов."""
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

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С ПРОФИЛЯМИ =====
    @retry_db
    def update_profile(self, key: str, profile_data: Dict) -> None:
        """Обновляет профиль."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO profiles (
                        key, server, protocol, first_seen, last_seen,
                        success_count, fail_count, latencies, timestamps,
                        sni_history, host_history, is_active, stability, lifetime, overall_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _compress(profile_data.get('sni_history', [])),
                    _compress(profile_data.get('host_history', [])),
                    1 if profile_data.get('is_active', True) else 0,
                    profile_data.get('stability', 0.0),
                    profile_data.get('lifetime', 0.0),
                    profile_data.get('overall_score', 0.0)
                ))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to update profile {key}: {e}")
                raise
        invalidate_decompress_cache()

    @retry_db
    def update_profiles_batch(self, profiles: List[Dict]) -> None:
        """Обновляет пачку профилей (с транзакцией)."""
        if not profiles:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                rows = []
                for profile_data in profiles:
                    key = profile_data.get('key', '')
                    if not key:
                        continue
                    rows.append((
                        key,
                        profile_data.get('server', ''),
                        profile_data.get('protocol', ''),
                        profile_data.get('first_seen', datetime.now().isoformat()),
                        profile_data.get('last_seen', datetime.now().isoformat()),
                        profile_data.get('success_count', 0),
                        profile_data.get('fail_count', 0),
                        _compress(profile_data.get('latencies', [])),
                        _compress(profile_data.get('timestamps', [])),
                        _compress(profile_data.get('sni_history', [])),
                        _compress(profile_data.get('host_history', [])),
                        1 if profile_data.get('is_active', True) else 0,
                        profile_data.get('stability', 0.0),
                        profile_data.get('lifetime', 0.0),
                        profile_data.get('overall_score', 0.0)
                    ))
                if rows:
                    cursor.executemany('''
                        INSERT OR REPLACE INTO profiles (
                            key, server, protocol, first_seen, last_seen,
                            success_count, fail_count, latencies, timestamps,
                            sni_history, host_history, is_active, stability, lifetime, overall_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', rows)
                conn.commit()
                logger.debug(f"Batch updated {len(rows)} profiles in SQLite")
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to batch update profiles: {e}")
                raise
        invalidate_decompress_cache()

    @retry_db
    def get_profile(self, key: str) -> Optional[Dict]:
        """Возвращает профиль по ключу."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profiles WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['sni_history'] = _decompress(row['sni_history']) or []
                d['host_history'] = _decompress(row['host_history']) or []
                d['is_active'] = bool(row['is_active'])
                return d
            return None

    @retry_db
    def get_all_profiles(self) -> List[Dict]:
        """Возвращает все профили."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM profiles')
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['latencies'] = _decompress(row['latencies']) or []
                d['timestamps'] = _decompress(row['timestamps']) or []
                d['sni_history'] = _decompress(row['sni_history']) or []
                d['host_history'] = _decompress(row['host_history']) or []
                d['is_active'] = bool(row['is_active'])
                result.append(d)
            return result

    @retry_db
    def get_profile_last_seen(self, key: str) -> Optional[str]:
        """Возвращает время последнего обновления профиля."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT last_seen FROM profiles WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                return row['last_seen']
            return None

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С ПРОВЕРКАМИ (PROBE HISTORY) =====
    @retry_db
    def add_probe_results_batch(self, results: List[Dict]) -> None:
        """Добавляет пачку результатов проверок (с транзакцией)."""
        if not results:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                rows = [(
                    item.get('profile_key', ''),
                    item.get('timestamp', datetime.now().isoformat()),
                    1 if item.get('success') else 0,
                    item.get('latency', 0.0),
                    item.get('tls_handshake', 0.0),
                    item.get('http_first_byte', 0.0),
                    item.get('http_total', 0.0),
                    item.get('status_code', 0),
                    item.get('error'),
                    item.get('protocol'),
                    item.get('transport'),
                    item.get('sni_used'),
                    item.get('host_used'),
                    item.get('path_used'),
                    item.get('attempt_number', 1),
                    item.get('total_attempts', 1),
                ) for item in results if item.get('profile_key')]
                if rows:
                    cursor.executemany('''
                        INSERT INTO probe_history (
                            profile_key, timestamp, success, latency,
                            tls_handshake_latency, http_first_byte, http_total,
                            status_code, error_type, protocol, transport,
                            sni_used, host_used, path_used,
                            attempt_number, total_attempts
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', rows)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to add probe results batch: {e}")
                raise

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С МЕТАДАННЫМИ =====
    @retry_db
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Возвращает метаданные по ключу."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                try:
                    return json.loads(row['value'])
                except Exception:
                    return row['value']
            return default

    @retry_db
    def set_metadata(self, key: str, value: Any) -> None:
        """Устанавливает метаданные."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)
                ''', (key, json.dumps(value)))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to set metadata {key}: {e}")
                raise

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С ИСТОРИЕЙ КАНАЛОВ =====
    @retry_db
    def add_channel_history(self, url: str, run_id: int, metrics: Dict) -> None:
        """Добавляет запись в историю канала."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
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
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to add channel history for {url}: {e}")
                raise

    @retry_db
    def get_channel_history(self, url: str, limit: int = 10) -> List[Dict]:
        """Возвращает историю канала."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM channel_history
                WHERE url = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (url, limit))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['protocol_counts'] = _decompress(row['protocol_counts']) or {}
                result.append(d)
            return result

    @retry_db
    def get_channel_history_scores(self, url: str, days: int = 7) -> List[Dict]:
        """Возвращает историю оценок канала."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, overall_score FROM channel_history
                WHERE url = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            ''', (url, cutoff))
            rows = cursor.fetchall()
            return [{'timestamp': row['timestamp'], 'score': row['overall_score']} for row in rows]

    @retry_db
    def get_channel_long_term_score(self, url: str, days: int = 7) -> Optional[float]:
        """Возвращает средний score канала за период."""
        scores = self.get_channel_history_scores(url, days)
        valid_scores = [s['score'] for s in scores if s['score'] > 0]
        if not valid_scores:
            return None
        return sum(valid_scores) / len(valid_scores)

    @retry_db
    def vacuum(self) -> None:
        """Выполняет VACUUM для БД."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("VACUUM")
            logger.info("SQLite database vacuumed (space reclaimed).")

    # ===== МЕТОДЫ ДЛЯ КАРАНТИНА КАНАЛОВ =====
    @retry_db
    def init_channel_grace_state(self, url: str, grace_period: int) -> None:
        """Инициализирует запись карантина для канала."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO channel_grace (url, grace_remaining, last_updated)
                    VALUES (?, ?, ?)
                ''', (url, grace_period, datetime.now().isoformat()))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to init grace state for {url}: {e}")
                raise

    @retry_db
    def get_channel_grace_state(self, url: str) -> Optional[Dict]:
        """Возвращает состояние карантина для канала."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channel_grace WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    @retry_db
    def decrement_channel_grace(self, url: str) -> None:
        """Уменьшает grace_remaining на 1 (если > 0)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    UPDATE channel_grace
                    SET grace_remaining = MAX(0, grace_remaining - 1),
                        last_updated = ?
                    WHERE url = ?
                ''', (datetime.now().isoformat(), url))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to decrement grace for {url}: {e}")
                raise

    @retry_db
    def reset_channel_grace(self, url: str, grace_period: int) -> None:
        """Сбрасывает grace_remaining до полного значения."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    UPDATE channel_grace
                    SET grace_remaining = ?,
                        last_updated = ?
                    WHERE url = ?
                ''', (grace_period, datetime.now().isoformat(), url))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to reset grace for {url}: {e}")
                raise

    @retry_db
    def set_channel_grace(self, url: str, grace_remaining: int) -> None:
        """Устанавливает конкретное значение grace_remaining."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN TRANSACTION")
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO channel_grace (url, grace_remaining, last_updated)
                    VALUES (?, ?, ?)
                ''', (url, grace_remaining, datetime.now().isoformat()))
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to set grace for {url}: {e}")
                raise


# Глобальный экземпляр БД
_db: Optional[HistoryDB] = None


def get_db() -> HistoryDB:
    """Возвращает глобальный экземпляр БД."""
    global _db
    if _db is None:
        _db = HistoryDB()
    return _db
