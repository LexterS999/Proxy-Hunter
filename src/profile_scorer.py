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
"""

import json
import os
import logging
import numpy as np
import requests
from typing import Dict, Optional, Tuple, List
from datetime import datetime, timedelta

from geo_loader import GeoLoader
from user_settings import GEO_COUNTRY_URL, GEO_ASN_URL, SCORE_WEIGHTS, DECAY_PERIOD_HOURS

logger = logging.getLogger(__name__)

class ProfileScorer:
    def __init__(self, history_file: str = 'configs/quality_history.json'):
        self.history_file = history_file
        self.history = self._load_history()
        self.geo = GeoLoader(GEO_COUNTRY_URL, GEO_ASN_URL)
        self._server_type_cache = {}  # Кеш для fallback-запросов

    def _load_history(self) -> Dict:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    if 'profiles' not in data:
                        data['profiles'] = {}
                    if 'runs' not in data:
                        data['runs'] = []
                    if 'thresholds' not in data:
                        data['thresholds'] = {}
                    return data
            except Exception as e:
                logger.warning(f"Failed to load history, creating new: {e}")
        return {
            'profiles': {},
            'runs': [],
            'thresholds': {}
        }

    def _save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")

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
        if key not in self.history['profiles']:
            self.history['profiles'][key] = {
                'first_seen': now,
                'last_seen': now,
                'success_count': 0,
                'fail_count': 0,
                'latencies': [],
                'scores': [],
                'timestamps': [],
                'is_active': True,
                'server': parsed.get('address') or parsed.get('add') or parsed.get('host'),
                'protocol': config.split('://')[0].lower()
            }
        profile = self.history['profiles'][key]
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
        self._save_history()

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
        """Определяет, является ли сервер датацентром, с использованием локальной базы и fallback."""
        if not server_ip:
            return False, 'UNK'
        # Проверяем кеш
        if server_ip in self._server_type_cache:
            return self._server_type_cache[server_ip]

        # 1. Пробуем локальный GeoLoader
        self.geo.ensure_databases()
        is_dc = self.geo.is_datacenter(server_ip)
        if is_dc:
            result = (True, 'DC')
            self._server_type_cache[server_ip] = result
            return result

        # 2. Fallback: запрос к ipinfo.io (синхронный, с таймаутом)
        try:
            response = requests.get(f"https://ipinfo.io/{server_ip}/json", timeout=5)
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
        """
        Рассчитывает репутацию на основе:
        - страна (предпочтение определённым странам)
        - является ли датацентром (датацентры часто имеют более стабильные соединения)
        - в будущем можно добавить privacy-флаги (is_vpn, is_proxy и т.д.)
        """
        if not server_ip:
            return 0.5

        self.geo.ensure_databases()
        country_code, _ = self.geo.get_country(server_ip)
        is_dc, _ = self.get_server_type(server_ip)

        # Базовый рейтинг
        score = 0.5

        # Страны с хорошей репутацией
        good_countries = {
            # Западная и Центральная Европа
            'US', 'DE', 'NL', 'UK', 'FR', 'CA', 'CH', 'SE', 'NO', 'DK', 'FI',
            'BE', 'AT', 'IE', 'LU', 'ES', 'IT', 'PT', 'GR',
        
            # Азиатско-Тихоокеанский регион
            'JP', 'SG', 'AU', 'NZ', 'KR', 'HK', 'TW', 'MY', 'TH',
            'IL', 'AE', 'QA', 'SA',
        
            # Восточная Европа и Прибалтика (растущие IT-хабы)
            'EE', 'LV', 'LT', 'PL', 'CZ', 'HU', 'SI', 'HR',
        
            # Северная и Южная Америка (кроме США и Канады)
            'CL', 'UY', 'CR', 'PA',
        }
        if country_code in good_countries:
            score += 0.2
        elif country_code == 'XX':
            score -= 0.1

        # Датацентры часто дают более стабильные соединения
        if is_dc:
            score += 0.2

        # Ограничиваем
        return max(0, min(1, score))

    def get_privacy_flags(self, server_ip: str) -> Dict[str, bool]:
        """
        Возвращает словарь с privacy-флагами.
        Сейчас заглушка — можно расширить, подключив другую базу данных.
        """
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
        stability = self.calculate_stability(profile)
        lifetime = self.calculate_lifetime_prediction(profile)
        config_quality = self.calculate_config_quality('', parsed)
        reputation = self.get_reputation_score(server_ip)

        total = profile['success_count'] + profile['fail_count']
        success_rate = profile['success_count'] / total if total > 0 else 0.5

        # Для новых профилей даём базовые значения
        if len(profile.get('timestamps', [])) < 2:
            stability = 0.7
            lifetime = 24.0
            success_rate = 0.7

        # Используем веса из настроек
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
        profile = self.history['profiles'].get(key)
        if not profile:
            return {'score': 50, 'stability': 0.5, 'lifetime': 24, 'is_datacenter': False, 'server_type': 'UNK'}
        server_ip = profile.get('server')
        is_dc, server_type = self.get_server_type(server_ip)
        stability = self.calculate_stability(profile)
        lifetime = self.calculate_lifetime_prediction(profile)
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
