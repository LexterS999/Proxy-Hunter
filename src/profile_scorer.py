"""
Модуль для оценки качества прокси-профилей на основе истории,
без использования активных пингов и без GeoIP.
"""

import json
import os
import logging
import numpy as np
from typing import Dict, Optional, Tuple, List
from datetime import datetime

from db import HistoryDB
from user_settings import SCORE_WEIGHTS  # добавлен импорт

logger = logging.getLogger(__name__)

class ProfileScorer:
    def __init__(self):
        self.db = HistoryDB()

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
        now = datetime.now().isoformat()

        profile = self.db.get_profile(key)
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
            if isinstance(profile.get('latencies'), bytes):
                import zlib
                try:
                    profile['latencies'] = json.loads(zlib.decompress(profile['latencies']).decode())
                except:
                    profile['latencies'] = []
            if isinstance(profile.get('timestamps'), bytes):
                try:
                    profile['timestamps'] = json.loads(zlib.decompress(profile['timestamps']).decode())
                except:
                    profile['timestamps'] = []
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

        self.db.update_profile(key, profile)

    def calculate_stability(self, profile: Dict) -> float:
        latencies = profile.get('latencies', [])
        if len(latencies) < 3:
            return 0.5
        mean = np.mean(latencies)
        if mean == 0:
            return 0.5
        std = np.std(latencies)
        cv = std / mean
        stability = max(0, min(1, 1 - cv))
        total = profile['success_count'] + profile['fail_count']
        if total > 0:
            success_rate = profile['success_count'] / total
            stability = stability * 0.7 + success_rate * 0.3
        return round(stability, 4)

    def calculate_lifetime_prediction(self, profile: Dict) -> float:
        timestamps = profile.get('timestamps', [])
        if len(timestamps) < 2:
            return 24.0
        times = [datetime.fromisoformat(ts) for ts in timestamps if ts]
        if len(times) < 2:
            return 24.0
        intervals = [(times[i] - times[i-1]).total_seconds() / 3600 for i in range(1, len(times))]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        if avg_interval == 0:
            return 24.0
        total = profile['success_count'] + profile['fail_count']
        success_rate = profile['success_count'] / total if total > 0 else 0.5
        lifetime = avg_interval * success_rate * 2
        return max(1, round(lifetime, 2))

    def calculate_config_quality(self, config: str, parsed: Dict) -> float:
        score = 1.0
        if not parsed.get('address') and not parsed.get('add'):
            score -= 0.3
        if not parsed.get('port'):
            score -= 0.3
        protocol = config.split('://')[0].lower() if config else ''
        if protocol == 'vless':
            if not parsed.get('uuid'):
                score -= 0.3
            if parsed.get('encryption') == 'none':
                score -= 0.1
            if parsed.get('flow'):
                score += 0.1
        elif protocol == 'vmess':
            if not parsed.get('id'):
                score -= 0.3
        elif protocol == 'trojan':
            if not parsed.get('password'):
                score -= 0.3
        elif protocol == 'ss':
            if not parsed.get('method') or not parsed.get('password'):
                score -= 0.3
        if parsed.get('sni'):
            score += 0.1
        if parsed.get('pbk'):
            score += 0.1
        if parsed.get('fp'):
            score += 0.05
        return max(0, min(1, round(score, 2)))

    def calculate_composite_score(self, profile: Dict, parsed: Dict) -> float:
        stability = profile.get('stability', 0.5)
        lifetime = profile.get('lifetime', 24.0)
        total = profile['success_count'] + profile['fail_count']
        success_rate = profile['success_count'] / total if total > 0 else 0.5
        config_quality = self.calculate_config_quality('', parsed)

        # Репутация фиксирована (0.5), без гео
        reputation = 0.5

        if len(profile.get('timestamps', [])) < 2:
            stability = 0.7
            lifetime = 24.0
            success_rate = 0.7

        w = SCORE_WEIGHTS
        score = (w['stability'] * stability +
                 w['success_rate'] * success_rate +
                 w['reputation'] * reputation +
                 w['lifetime'] * (lifetime / 48) +
                 w['config_quality'] * config_quality)
        score = max(0, min(100, score * 100))
        return round(score, 2)

    def score_profile(self, config: str, parsed: Dict, success: bool = True,
                      latency: float = 0) -> Dict:
        self.update_profile_history(config, parsed, success, latency)
        key = self.get_profile_key(config, parsed)
        profile = self.db.get_profile(key)
        if not profile:
            return {'score': 50, 'stability': 0.5, 'lifetime': 24, 'is_datacenter': False, 'server_type': 'UNK'}

        stability = profile.get('stability', 0.5)
        lifetime = profile.get('lifetime', 24.0)
        composite = self.calculate_composite_score(profile, parsed)

        return {
            'score': composite,
            'stability': stability,
            'lifetime': lifetime,
            'is_datacenter': False,
            'server_type': 'UNK',
            'config_quality': self.calculate_config_quality(config, parsed),
            'reputation': 0.5,
            'privacy': {}
        }
