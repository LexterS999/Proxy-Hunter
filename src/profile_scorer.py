"""
Пассивный и коммитный скоринг профилей.

Ключевые исправления:
- пассивный скор больше не загрязняет историю фиктивным success=True;
- исправлен расчёт drift для SNI/Host (раньше стабильные значения штрафовались);
- исправлен региональный множитель (теперь он применяется к base_score, а не заменяет его);
- сохранены и переиспользуются SNI/host истории между запусками.
"""

import logging
import math
from datetime import datetime
from typing import Dict, Optional, List

import numpy as np

from db import get_db
from user_settings import SCORE_WEIGHTS
from regional_scorer import RegionalScorer
from regional_stats import RegionalStats

logger = logging.getLogger(__name__)


class ProfileScorer:
    def __init__(self, region: str = 'RU'):
        self.db = get_db()
        self._profile_cache: Dict[str, Dict] = {}
        self._dirty_keys = set()
        self._batch_size = 100
        self._last_flush = datetime.now()
        self._flush_interval = 60
        self.region = region
        self.regional_scorer = RegionalScorer(region)
        self.regional_stats = RegionalStats()
        self._has_history_cache: Optional[bool] = None

    def __del__(self):
        try:
            self._flush_profiles()
        except Exception:
            pass

    def _get_cached_profile(self, key: str) -> Optional[Dict]:
        if key not in self._profile_cache:
            profile = self.db.get_profile(key)
            if profile:
                self._profile_cache[key] = profile
        return self._profile_cache.get(key)

    def _update_profile_cached(self, key: str, updates: Dict):
        if key not in self._profile_cache:
            self._profile_cache[key] = self.db.get_profile(key) or {}
        self._profile_cache[key].update(updates)
        self._dirty_keys.add(key)
        if len(self._dirty_keys) >= self._batch_size or (datetime.now() - self._last_flush).total_seconds() > self._flush_interval:
            self._flush_profiles()

    def _flush_profiles(self):
        if not self._dirty_keys:
            return
        profiles_to_save = []
        for key in list(self._dirty_keys):
            profile = self._profile_cache.get(key)
            if profile:
                profiles_to_save.append(profile)
        if profiles_to_save:
            self.db.update_profiles_batch(profiles_to_save)
        self._dirty_keys.clear()
        self._last_flush = datetime.now()

    def get_profile_key(self, config: str, parsed: Dict) -> str:
        protocol = (parsed.get('protocol') or config.split('://')[0]).lower()
        server = parsed.get('address') or parsed.get('add') or parsed.get('host') or ''
        port = parsed.get('port') or 0
        if protocol == 'vless':
            credential = parsed.get('uuid', '')
        elif protocol == 'vmess':
            credential = parsed.get('id', '')
        elif protocol == 'trojan':
            credential = parsed.get('password', '')
        elif protocol == 'ss':
            credential = f"{parsed.get('method', '')}:{parsed.get('password', '')}"
        elif protocol in ('hysteria2', 'hy2'):
            credential = parsed.get('password', '')
        elif protocol == 'tuic':
            credential = f"{parsed.get('uuid', '')}:{parsed.get('password', '')}"
        else:
            credential = 'default'
        return f"{server}:{port}:{protocol}:{credential}"

    def _build_new_profile(self, key: str, config: str, parsed: Dict, now: str) -> Dict:
        return {
            'key': key,
            'server': parsed.get('address') or parsed.get('add') or parsed.get('host'),
            'protocol': (parsed.get('protocol') or config.split('://')[0]).lower(),
            'first_seen': now,
            'last_seen': now,
            'success_count': 0,
            'fail_count': 0,
            'latencies': [],
            'timestamps': [],
            'sni_history': [],
            'host_history': [],
            'is_active': True,
            'stability': 0.5,
            'lifetime': 24.0,
            'overall_score': 0.0,
        }

    def _trim_profile(self, profile: Dict, max_history: int = 100) -> Dict:
        for field in ('latencies', 'timestamps', 'sni_history', 'host_history'):
            values = profile.get(field, []) or []
            if len(values) > max_history:
                profile[field] = values[-max_history:]
        return profile

    def update_profile_history(
        self,
        config: str,
        parsed: Dict,
        success: bool,
        latency: float = 0,
        sni_used: str = None,
        host_used: str = None,
    ) -> Dict:
        key = self.get_profile_key(config, parsed)
        now = datetime.now().isoformat()
        profile = self._get_cached_profile(key)
        if not profile:
            profile = self._build_new_profile(key, config, parsed, now)
        else:
            profile['last_seen'] = now

        if success:
            profile['success_count'] = int(profile.get('success_count', 0)) + 1
        else:
            profile['fail_count'] = int(profile.get('fail_count', 0)) + 1

        if latency > 0:
            profile.setdefault('latencies', []).append(float(latency))
        profile.setdefault('timestamps', []).append(now)

        resolved_sni = sni_used or parsed.get('sni') or parsed.get('serverName')
        resolved_host = host_used or parsed.get('host') or parsed.get('authority') or parsed.get('address') or parsed.get('add')
        if resolved_sni:
            profile.setdefault('sni_history', []).append(resolved_sni)
        if resolved_host:
            profile.setdefault('host_history', []).append(resolved_host)

        self._trim_profile(profile)
        profile['stability'] = self.calculate_stability(profile)
        profile['lifetime'] = self.calculate_lifetime_prediction(profile)
        self._update_profile_cached(key, profile)
        return profile

    def calculate_stability(self, profile: Dict) -> float:
        latencies = [float(v) for v in (profile.get('latencies') or []) if float(v) > 0]
        total = int(profile.get('success_count', 0)) + int(profile.get('fail_count', 0))
        smoothed_success = (int(profile.get('success_count', 0)) + 1) / (total + 2) if total >= 0 else 0.5

        if len(latencies) >= 3:
            mean = float(np.mean(latencies))
            std = float(np.std(latencies))
            cv = std / mean if mean > 0 else 1.0
            latency_stability = max(0.0, min(1.0, 1.0 - min(cv, 1.5) / 1.5))
        else:
            latency_stability = 0.55

        def variability(history: List[str]) -> float:
            values = [v for v in (history or []) if v]
            if len(values) < 2:
                return 0.0
            unique = len(set(values))
            return min(1.0, max(0.0, (unique - 1) / (len(values) - 1)))

        sni_variability = variability(profile.get('sni_history', []))
        host_variability = variability(profile.get('host_history', []))

        stability = (
            latency_stability * 0.60 +
            smoothed_success * 0.25 +
            (1.0 - sni_variability) * 0.10 +
            (1.0 - host_variability) * 0.05
        )
        return round(max(0.0, min(1.0, stability)), 4)

    def calculate_lifetime_prediction(self, profile: Dict) -> float:
        timestamps = [ts for ts in (profile.get('timestamps') or []) if ts]
        if not timestamps:
            return 24.0

        try:
            times = [datetime.fromisoformat(ts) for ts in timestamps]
        except Exception:
            return 24.0

        total = int(profile.get('success_count', 0)) + int(profile.get('fail_count', 0))
        smoothed_success = (int(profile.get('success_count', 0)) + 1) / (total + 2) if total >= 0 else 0.5

        if len(times) < 2:
            return round(max(6.0, 24.0 * smoothed_success), 2)

        intervals = [
            (times[i] - times[i - 1]).total_seconds() / 3600.0
            for i in range(1, len(times))
            if (times[i] - times[i - 1]).total_seconds() > 0
        ]
        if not intervals:
            return 24.0

        avg_interval = float(np.mean(intervals))
        p90_interval = float(np.percentile(intervals, 90)) if len(intervals) >= 2 else avg_interval
        age_hours = max(0.0, (datetime.now() - times[-1]).total_seconds() / 3600.0)
        freshness_penalty = max(0.35, math.exp(-age_hours / 72.0))
        lifetime = max(4.0, min(168.0, (avg_interval * 1.5 + p90_interval * 0.5) * smoothed_success * freshness_penalty))
        return round(lifetime, 2)

    def calculate_config_quality(self, config: str, parsed: Dict) -> float:
        score = 1.0
        protocol = (parsed.get('protocol') or (config.split('://')[0].lower() if config else '')).lower()
        if protocol not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2', 'tuic'):
            score -= 0.30

        address = parsed.get('address') or parsed.get('add') or parsed.get('host')
        if not address:
            score -= 0.25
        if not parsed.get('port'):
            score -= 0.25

        if protocol == 'vless':
            if not parsed.get('uuid'):
                score -= 0.30
            if parsed.get('encryption') == 'none':
                score -= 0.05
            if parsed.get('flow'):
                score += 0.08
        elif protocol == 'vmess':
            if not parsed.get('id'):
                score -= 0.30
            if parsed.get('tls') in ('tls', 'reality'):
                score += 0.05
        elif protocol == 'trojan':
            if not parsed.get('password'):
                score -= 0.30
        elif protocol == 'ss':
            if not parsed.get('method') or not parsed.get('password'):
                score -= 0.30
            elif parsed.get('method', '').lower() in {'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'}:
                score += 0.05

        if parsed.get('sni'):
            score += 0.08
        if parsed.get('pbk'):
            score += 0.08
        if parsed.get('fp'):
            score += 0.04
        if parsed.get('security') == 'reality':
            score += 0.10
        if parsed.get('alpn'):
            score += 0.03
        return round(max(0.0, min(1.0, score)), 4)

    def _has_history(self) -> bool:
        if self._has_history_cache is None:
            try:
                self._has_history_cache = len(self.db.get_recent_runs(1)) > 0
            except Exception:
                self._has_history_cache = False
        return self._has_history_cache

    def calculate_composite_score(self, config: str, profile: Dict, parsed: Dict) -> float:
        stability = float(profile.get('stability', 0.5))
        lifetime = float(profile.get('lifetime', 24.0))
        config_quality = self.calculate_config_quality(config, parsed)
        success_count = int(profile.get('success_count', 0))
        fail_count = int(profile.get('fail_count', 0))
        total = success_count + fail_count
        success_rate = (success_count + 1) / (total + 2)

        last_seen = profile.get('last_seen')
        freshness = 0.7
        if last_seen:
            try:
                age_hours = max(0.0, (datetime.now() - datetime.fromisoformat(last_seen)).total_seconds() / 3600.0)
                freshness = max(0.25, min(1.0, math.exp(-age_hours / 72.0)))
            except Exception:
                freshness = 0.7

        maturity = min(1.0, total / 10.0) if total > 0 else 0.0
        reputation = min(1.0, 0.35 + 0.35 * maturity + 0.30 * freshness)
        lifetime_norm = min(1.0, lifetime / 72.0)

        w = SCORE_WEIGHTS
        base_score = (
            w['stability'] * stability +
            w['success_rate'] * success_rate +
            w['reputation'] * reputation +
            w['lifetime'] * lifetime_norm +
            w['config_quality'] * config_quality
        ) * 100.0
        base_score *= (0.85 + 0.15 * freshness)
        base_score = max(0.0, min(100.0, base_score))

        if self._has_history():
            region_score = self.regional_scorer.calculate_region_score(config=config, parsed=parsed, base_score=base_score)
            adjustment = self.regional_stats.compute_adjustment(config=config, parsed=parsed, region=self.region)
            final_score = max(0.0, min(100.0, region_score * adjustment))
        else:
            final_score = base_score
        return round(final_score, 2)

    def _score_dict(self, config: str, profile: Dict, parsed: Dict) -> Dict:
        stability = float(profile.get('stability', 0.5))
        lifetime = float(profile.get('lifetime', 24.0))
        composite = self.calculate_composite_score(config, profile, parsed)
        return {
            'score': composite,
            'stability': stability,
            'lifetime': lifetime,
            'is_datacenter': False,
            'server_type': 'UNK',
            'config_quality': self.calculate_config_quality(config, parsed),
            'reputation': min(1.0, 0.35 + 0.35 * min(1.0, (profile.get('success_count', 0) + profile.get('fail_count', 0)) / 10.0)),
            'privacy': {},
        }

    def preview_score(self, config: str, parsed: Dict) -> Dict:
        key = self.get_profile_key(config, parsed)
        profile = self._get_cached_profile(key)
        if not profile:
            profile = self._build_new_profile(key, config, parsed, datetime.now().isoformat())
            profile['stability'] = 0.5
            profile['lifetime'] = 24.0
        return self._score_dict(config, profile, parsed)

    def score_profile(
        self,
        config: str,
        parsed: Dict,
        success: bool = True,
        latency: float = 0,
        sni_used: str = None,
        host_used: str = None,
    ) -> Dict:
        profile = self.update_profile_history(config, parsed, success, latency, sni_used, host_used)
        result = self._score_dict(config, profile, parsed)
        profile['overall_score'] = result['score']
        profile['is_active'] = bool(success)
        self._update_profile_cached(profile['key'], profile)
        return result

    def record_local_result(self, config: str, parsed: Dict, success: bool, latency: float):
        self.regional_stats.record_local_check(config, parsed, success, latency, region=self.region)
