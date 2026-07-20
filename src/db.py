"""
Модуль для работы с SQLite-базой данных истории.
Хранит статистику запусков, каналов и профилей с компрессией.
Добавлены индексы, TTL-кеш для распаковки, WAL-режим.

ИСПРАВЛЕНО: lru_cache заменён на TTL-кеш с инвалидацией.
"""

import sqlite3
import json
import zlib
import logging
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager
from collections import OrderedDict

logger = logging.getLogger(__name__)

DB_PATH = "configs/history.db"
COMPRESS_LEVEL = 6  # уровень сжатия zlib


def _compress(data: Any) -> bytes:
    """Сжимает JSON-данные в bytes."""
    if data is None:
        return b''
    try:
        return zlib.compress(json.dumps(data).encode('utf-8'), level=COMPRESS_LEVEL)
    except Exception:
        return b''


class TTLCache:
    """
    Кеш с TTL-инвалидацией для распакованных blobs.
    Потокобезопасен. Автоматически удаляет устаревшие записи.
    """

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
                    # Перемещаем в конец (LRU)
                    self._cache.move_to_end(blob)
                    return value
                else:
                    # Устарело — удаляем
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
                    self._cache.popitem(last=False)  # Удаляем самый старый
                self._cache[blob] = (time.time(), value)

    def invalidate(self) -> None:
        """Полная инвалидация кеша (при обновлении данных в БД)."""
        with self._lock:
            self._cache.clear()

    def invalidate_prefix(self, prefix: bytes) -> None:
        """Инвалидация записей по префиксу (для точечных обновлений)."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._cache[k]


# Глобальный TTL-кеш для распаковки
_decompress_cache = TTLCache(maxsize=1024, ttl_seconds=300.0)


def _decompress_cached(blob: bytes) -> Any:
    """Распаковывает bytes в JSON-объект с TTL-кешированием."""
    if blob is None or not blob:
        return None

    # Проверяем кеш
    cached = _decompress_cache.get(blob)
    if cached is not None:
        return cached

    # Распаковываем
    try:
        result = json.loads(zlib.decompress(blob).decode('utf-8'))
        _decompress_cache.put(blob, result)
        return result
    except Exception:
        return None


def _decompress(blob: bytes) -> Any:
    """Обёртка для обратной совместимости."""
    return _decompress_cached(blob)


def invalidate_decompress_cache() -> None:
    """Публичная функция для инвалидации кеша распаковки (вызывать после UPDATE в БД)."""
    _decompress_cache.invalidate()


class HistoryDB:
    """Синглтон для доступа к SQLite базе истории с индексами и WAL."""

    _instance: Optional['HistoryDB'] = None

    def __new__(cls) -> 'HistoryDB':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self) -> None:
        """Создаёт таблицы и индексы, включает WAL."""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
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

            # Индексы (добавляем, если их нет)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_url ON channel_history(url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_timestamp ON channel_history(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_history_run_id ON channel_history(run_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_server ON profiles(server)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON profiles(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp)")

            conn.commit()
            logger.info("SQLite history database initialized with indexes and WAL.")

    @contextmanager
    def _get_connection(self):
        """Контекстный менеджер для соединения с БД."""
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ----- Методы для работы с runs -----
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

    def get_last_run(self) -> Optional[Dict]:
        runs = self.get_recent_runs(1)
        return runs[0] if runs else None

    # ----- Методы для работы с каналами -----
    def update_channel(self, url: str, metrics: Dict, enabled: bool = True) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
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
        # Инвалидируем кеш после записи
        invalidate_decompress_cache()

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

    # ----- Методы для работы с профилями -----
    def update_profile(self, key: str, profile_data: Dict) -> None:
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
        # Инвалидируем кеш после записи
        invalidate_decompress_cache()

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

    # ----- Методы для метаданных -----
    def get_metadata(self, key: str, default: Any = None) -> Any:
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

    def set_metadata(self, key: str, value: Any) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)
            ''', (key, json.dumps(value)))
            conn.commit()

    # ----- Методы для истории каналов -----
    def add_channel_history(self, url: str, run_id: int, metrics: Dict) -> None:
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

    def get_channel_history_scores(self, url: str, days: int = 7) -> List[Dict]:
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

    def get_channel_long_term_score(self, url: str, days: int = 7) -> Optional[float]:
        scores = self.get_channel_history_scores(url, days)
        valid_scores = [s['score'] for s in scores if s['score'] > 0]
        if not valid_scores:
            return None
        return sum(valid_scores) / len(valid_scores)


# Инициализация
_db = HistoryDB()
