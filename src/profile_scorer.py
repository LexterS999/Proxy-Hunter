"""
Модуль для оценки качества прокси-профилей на основе истории,
без использования активных пингов и без GeoIP.
"""

import json
import os
import logging
import numpy as np
from typing import Dict, Optional, Tuple, List
from datetime import datetime, timedelta, timezone
import math
import asyncio

from db import get_db
from user_settings import SCORE_WEIGHTS

logger = logging.getLogger(__name__)


class ProfileScorer:
    def __init__(self):
        self.db = get_db()
        self._profile_cache = {}
        self._dirty_keys = set()
        self._batch_size = 100
        self._last_flush = datetime.now(timezone.utc)
        self._flush_interval = 60

    def __del__(self):
        """Гарантированная запись при завершении."""
        try:
            asyncio.run(self._flush_profiles_async())
        except Exception:
            pass

    async def _flush_profiles_async(self):
        if not self._dirty_keys:
            return
        profiles_to_save = []
        for key in list(self._dirty_keys):
            profile = self._profile_cache.get(key)
            if profile:
                profiles_to_save.append(profile)
        if profiles_to_save:
            await self.db.update_profiles_batch(profiles_to_save)
        self._dirty_keys.clear()
        self._last_flush = datetime.now(timezone.utc)

    def _get_cached_profile(self, key: str) -> Optional[Dict]:
        if key not in self._profile_cache:
            try:
                profile = asyncio.run(self.db.get_profile(key))
                if profile:
                    self._profile_cache[key] = profile
            except Exception:
                pass
        return self._profile_cache.get(key)

    def _update_profile_cached(self, key: str, updates: Dict):
        if key not in self._profile_cache:
            self._profile_cache[key] = asyncio.run(self.db.get_profile(key)) or {}
        self._profile_cache[key].update(updates)
        self._dirty_keys.add(key)
        if len(self._dirty_keys) >= self._batch_size or \
           (datetime.now(timezone.utc) - self._last_flush).seconds > self._flush_interval:
            try:
                asyncio.run(self._flush_profiles_async())
            except Exception:
                pass

    def get_profile_key(self, config: str, parsed: Dict) -> str:
        protocol = config.split('://')[0].lower()
        server = parsed.get('address') or parsed.get('add') or parsed.get('host')
        port = parsed.get('port')
        if protocol == 'vless':
            credential = parsed.get('uuid', '')
        elif protocol == 'vmess':
            credential = parsed.get('id', '')
        elif protocol == 'trojan':
            credential = parsed.get('password', '')
        elif protocol == 'ss':
            credential = f"{parsed.get('method', '')}:{parsed.get('password', '')}"
        else:
            credential = 'default'
        return f"{server}:{port}:{protocol}:{credential}"

    def update_profile_history(self, config: str, parsed: Dict,
                               success: bool, latency: float = 0):
        key = self.get_profile_key(config, parsed)
        now = datetime.now(timezone.utc).isoformat()

        profile = self._get_cached_profile(key)
        if not profile:
            profile = {
                'key': key,
                'server': parsed.get('address') or parsed.get('add') or parsed.get('host'),
                'protocol': config.split('://')[0].lower(),
                'first_seen': now,
                'last_seen': now,
                'success_count': 0,
                'fail_count': 0,
                'latencies': [],
                'timestamps': [],
                'is_active': True,
                'stability': 0.0,
                'lifetime': 0.0,
                'overall_score': 0.0
            }
        else:
            profile['last_seen'] = now

        if success:
            profile['success_count'] += 1
        else:
            profile['fail_count'] += 1
        if latency > 0:
            profile['latencies'].append(latency)
        profile['timestamps'].append(now)

        max_history = 100
        if len(profile['latencies']) > max_history:
            profile['latencies'] = profile['latencies'][-max_history:]
        if len(profile['timestamps']) > max_history:
            profile['timestamps'] = profile['timestamps'][-max_history:]

        profile['stability'] = self.calculate_stability(profile)
        profile['lifetime'] = self.calculate_lifetime_prediction(profile)

        self._update_profile_cached(key, profile)

    def calculate_stability(self, profile: Dict) -> float:
        latencies = profile.get('latencies', [])
        if not latencies:
            return 0.5
        if len(latencies) < 3:
            return 0.5
        mean = np.mean(latencies)
        if mean == 0:
            return 0.5
        std = np.std(latencies)
        cv = std / mean if mean > 0 else 1
        stability = max(0, min(1, 1 - cv))
        total = profile['success_count'] + profile['fail_count']
        if total > 0:
            success_rate = profile['success_count'] / total
            stability = stability * 0.7 + success_rate * 0.3
        return round(stability, 4)

    def calculate_lifetime_prediction(self, profile: Dict) -> float:
        timestamps = profile.get('timestamps', [])
        if not timestamps:
            return 24.0

        times = [datetime.fromisoformat(ts) for ts in timestamps if ts]
        if len(times) < 2:
            total = profile['success_count'] + profile['fail_count']
            if total == 0:
                return 24.0
            success_rate = profile['success_count'] / total
            return max(1, 24 * success_rate)

        intervals = [(times[i] - times[i-1]).total_seconds() / 3600 for i in range(1, len(times))]
        avg_interval
