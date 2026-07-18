"""
Модуль для оценки качества прокси-профилей на основе истории,
без использования активных пингов.
Рассчитывает:
- Stability Score (стабильность)
- Lifetime Prediction (прогнозируемое время жизни)
- Configuration Quality Score
- Композитный скор
- Старение (упрощённое)
- Дополнительные факторы: страна, ASN, датацентр, privacy-флаги
- Добавлен fallback через внешний API (ipinfo.io) с кешированием
- Теперь использует SQLite для хранения профилей (db.py)
"""

import json
import os
import logging
import numpy as np
import requests
import asyncio
from typing import Dict, Optional, Tuple, List
from datetime import datetime, timedelta

from geo_loader import GeoLoader
from user_settings import GEO_COUNTRY_URL, GEO_ASN_URL, SCORE_WEIGHTS, DECAY_PERIOD_HOURS
from db import HistoryDB

logger = logging.getLogger(__name__)

class ProfileScorer:
    def __init__(self):
        self.db = HistoryDB()  # Используем SQLite вместо JSON
        self.geo = GeoLoader(GEO_COUNTRY_URL, GEO_ASN_URL)
        self._server_type_cache = {}  # Кеш для fallback-запросов
        # Загружаем существующие профили из БД при инициализации (опционально)

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

        # Получаем существующий профиль из БД
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
            # Преобразуем поля (latencies, timestamps) из bytes в list, если нужно
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

        # Обновляем счётчики
        if success:
            profile['success_count'] += 1
        else:
            profile['fail_count'] += 1
        if latency > 0:
            profile['latencies'].append(latency)
        profile['timestamps'].append(now)

        # Ограничиваем историю
        max_history = 100
        if len(profile['latencies']) > max_history:
            profile['latencies'] = profile['latencies'][-max_history:]
        if len(profile['timestamps']) > max_history:
            profile['timestamps'] = profile['timestamps'][-max_history:]

        # Пересчитываем стабильность и lifetime (можно делать при каждом обновлении)
        profile['stability'] = self.calculate_stability(profile)
        profile['lifetime'] = self.calculate_lifetime_prediction(profile)

        # Сохраняем в БД
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
        avg_interval = sum(intervals) / len(intervals)
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

    def get_server_type(self, server_ip: str) -> Tuple[bool, str]:
        """
        Определяет, является ли сервер датацентром, с использованием локальной базы.
        fallback к ipinfo.io теперь асинхронный (но для простоты оставим синхронный с малым таймаутом,
        т.к. вызывается редко).
        """
        if not server_ip:
            return False, 'UNK'
        if server_ip in self._server_type_cache:
            return self._server_type_cache[server_ip]

        self.geo.ensure_databases()
        is_dc = self.geo.is_datacenter(server_ip)
        if is_dc:
            result = (True, 'DC')
            self._server_type_cache[server_ip] = result
            return result

        # fallback: синхронный запрос к ipinfo.io с таймаутом 3 сек
        try:
            response = requests.get(f"https://ipinfo.io/{server_ip}/json", timeout=3)
            if response.status_code == 200:
                data = response.json()
                org = data.get('org', '')
                if 'hosting' in org.lower() or 'cloud' in org.lower():
                    result = (True, 'DC')
                    self._server_type_cache[server_ip] = result
                    return result
        except Exception as e:
            logger.debug(f"Fallback IP check failed for {server_ip}: {e}")

        result = (False, 'UNK')
        self._server_type_cache[server_ip] = result
        return result

    def get_reputation_score(self, server_ip: str) -> float:
        if not server_ip:
            return 0.5

        self.geo.ensure_databases()
        country_code, _ = self.geo.get_country(server_ip)
        is_dc, _ = self.get_server_type(server_ip)

        score = 0.5
        good_countries = {
            'US', 'DE', 'NL', 'UK', 'FR', 'CA', 'CH', 'SE', 'NO', 'DK', 'FI',
            'BE', 'AT', 'IE', 'LU', 'ES', 'IT', 'PT', 'GR',
            'JP', 'SG', 'AU', 'NZ', 'KR', 'HK', 'TW', 'MY', 'TH',
            'IL', 'AE', 'QA', 'SA',
            'EE', 'LV', 'LT', 'PL', 'CZ', 'HU', 'SI', 'HR',
            'CL', 'UY', 'CR', 'PA',
        }
        if country_code in good_countries:
            score += 0.2
        elif country_code == 'XX':
            score -= 0.1

        if is_dc:
            score += 0.2

        return max(0, min(1, score))

    def get_privacy_flags(self, server_ip: str) -> Dict[str, bool]:
        is_dc, _ = self.get_server_type(server_ip)
        return {
            'is_abuser': False,
            'is_anonymous': False,
            'is_bogon': False,
            'is_hosting': is_dc,
            'is_icloud_relay': False,
            'is_proxy': False,
            'is_tor': False,
            'is_vpn': False,
        }

    def calculate_composite_score(self, profile: Dict, parsed: Dict, server_ip: str) -> float:
        stability = profile.get('stability', 0.5)
        lifetime = profile.get('lifetime', 24.0)

        total = profile['success_count'] + profile['fail_count']
        success_rate = profile['success_count'] / total if total > 0 else 0.5

        config_quality = self.calculate_config_quality('', parsed)
        reputation = self.get_reputation_score(server_ip)

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
        # Обновляем историю
        self.update_profile_history(config, parsed, success, latency)
        key = self.get_profile_key(config, parsed)
        profile = self.db.get_profile(key)
        if not profile:
            return {'score': 50, 'stability': 0.5, 'lifetime': 24, 'is_datacenter': False, 'server_type': 'UNK'}

        server_ip = profile.get('server', '')
        is_dc, server_type = self.get_server_type(server_ip)
        stability = profile.get('stability', 0.5)
        lifetime = profile.get('lifetime', 24.0)
        composite = self.calculate_composite_score(profile, parsed, server_ip)
        privacy = self.get_privacy_flags(server_ip) if server_ip else {}

        return {
            'score': composite,
            'stability': stability,
            'lifetime': lifetime,
            'is_datacenter': is_dc,
            'server_type': server_type,
            'config_quality': self.calculate_config_quality(config, parsed),
            'reputation': self.get_reputation_score(server_ip),
            'privacy': privacy
        }
