import asyncio
import sqlite3
import json
import logging
from typing import Dict, Any
from datetime import datetime
import time

logger = logging.getLogger(__name__)

class AsyncDBWriter:
    _instance = None
    _queue = None
    _task = None
    _running = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._queue = None
            cls._instance._task = None
            cls._instance._running = False
        return cls._instance

    def _init(self):
        # вызывается из start() в цикле событий
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=1000)
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._worker())
            logger.info("AsyncDBWriter started")

    async def start(self):
        """Запускает воркер в текущем цикле событий."""
        self._init()

    async def _worker(self):
        conn = sqlite3.connect('configs/history.db')
        conn.row_factory = sqlite3.Row
        while self._running:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                if item is None:
                    break
                self._process_item(conn, item)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"AsyncDBWriter worker error: {e}")
        conn.close()
        logger.info("AsyncDBWriter stopped")

    def _process_item(self, conn, item: Dict):
        cursor = conn.cursor()
        if item['type'] == 'probe':
            cursor.execute('''
                INSERT INTO probe_history (
                    profile_key, timestamp, success, latency,
                    tls_handshake_latency, http_first_byte, http_total,
                    status_code, error_type, protocol, transport,
                    sni_used, host_used, path_used,
                    attempt_number, total_attempts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item['profile_key'],
                item.get('timestamp', datetime.now().isoformat()),
                1 if item['success'] else 0,
                item.get('latency', 0),
                item.get('tls_handshake', 0),
                item.get('http_first_byte', 0),
                item.get('http_total', 0),
                item.get('status_code', 0),
                item.get('error'),
                item.get('protocol'),
                item.get('transport'),
                item.get('sni_used'),
                item.get('host_used'),
                item.get('path_used'),
                item.get('attempt_number', 1),
                item.get('total_attempts', 1)
            ))
        elif item['type'] == 'features':
            columns = ', '.join(item['data'].keys())
            placeholders = ', '.join(['?'] * len(item['data']))
            cursor.execute(f'''
                INSERT OR REPLACE INTO profile_features ({columns})
                VALUES ({placeholders})
            ''', list(item['data'].values()))
        conn.commit()

    async def enqueue(self, item: Dict):
        if self._running and self._queue is not None:
            await self._queue.put(item)
        else:
            logger.warning("AsyncDBWriter is not running, dropping item")

    async def stop(self):
        self._running = False
        if self._queue is not None:
            await self._queue.put(None)
        if self._task is not None:
            await self._task
