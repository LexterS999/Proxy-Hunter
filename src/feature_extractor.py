import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
import numpy as np
from collections import defaultdict
from urllib.parse import urlparse

from config_identity import ConfigIdentity
from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks

logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self, db_path='configs/history.db'):
        self.db_path = db_path
        self._cache = {}
        self._conn = None

    def _get_conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self._conn

    def get_profile_key(self, config: str) -> str:
        endpoint = ConfigIdentity.get_endpoint(config)
        if endpoint:
            host, port, proto, cred = endpoint
            return f"{host}:{port}:{proto}:{cred}"
        return None

    def extract_from_parsed(self, config: str, parsed: dict) -> Dict:
        key = self.get_profile_key(config)
        if not key:
            return {}
        return self.extract_features(key, config, parsed)

    def extract_features(self, profile_key: str, config: str, parsed: dict) -> Dict:
        features = {
            'profile_key': profile_key,
            'protocol': parsed.get('protocol', 'unknown'),
            'transport': parsed.get('type', parsed.get('net', 'tcp')),
            'has_sni': 1 if parsed.get('sni') else 0,
            'has_host': 1 if parsed.get('host') else 0,
            'has_path': 1 if parsed.get('path') else 0,
            'has_pbk': 1 if parsed.get('pbk') else 0,
            'has_flow': 1 if parsed.get('flow') else 0,
            'is_reality': 1 if parsed.get('security') == 'reality' else 0,
            'alter_id': int(parsed.get('aid', 0)) if parsed.get('aid') else 0,
            'ss_method': parsed.get('method', ''),
            'config_length': len(config),
            'sni_count': 0,
            'host_count': 0,
            'path_count': 0,
            'same_ip_count': 0,
            'same_ip_success_rate': 0.0,
            'same_sni_count': 0,
        }

        # Агрегируем историю sni/host/path (изменяется в процессе)
        history = self._get_profile_history(profile_key)
        if history:
            sni_set = set()
            host_set = set()
            path_set = set()
            for rec in history:
                if rec.get('sni_used'):
                    sni_set.add(rec['sni_used'])
                if rec.get('host_used'):
                    host_set.add(rec['host_used'])
                if rec.get('path_used'):
                    path_set.add(rec['path_used'])
            features['sni_count'] = len(sni_set)
            features['host_count'] = len(host_set)
            features['path_count'] = len(path_set)

        # Статистические признаки из истории зондов
        stats = self._compute_stats(profile_key)
        features.update(stats)

        # Корреляционные признаки
        ip = parsed.get('address') or parsed.get('add')
        if ip:
            ip_stats = self._compute_ip_stats(ip, profile_key)
            features['same_ip_count'] = ip_stats['count']
            features['same_ip_success_rate'] = ip_stats['success_rate']
        sni = parsed.get('sni')
        if sni:
            features['same_sni_count'] = self._count_same_sni(sni, profile_key)

        return features

    def _compute_stats(self, profile_key: str) -> Dict:
        conn = self._get_conn()
        cursor = conn.cursor()
        windows = {
            '1h': 1,
            '6h': 6,
            '24h': 24,
            '7d': 168
        }
        result = {}
        for label, hours in windows.items():
            cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
            cursor.execute('''
                SELECT success, latency FROM probe_history
                WHERE profile_key = ? AND timestamp > ?
            ''', (profile_key, cutoff))
            rows = cursor.fetchall()
            latencies = [r[1] for r in rows if r[0] == 1 and r[1] > 0]
            successes = sum(1 for r in rows if r[0] == 1)
            total = len(rows)
            result[f'count_{label}'] = total
            result[f'success_{label}'] = successes
            result[f'avg_latency_{label}'] = np.mean(latencies) if latencies else 0.0
            if label == '24h':
                result[f'p90_latency_{label}'] = np.percentile(latencies, 90) if latencies else 0.0
                result[f'p99_latency_{label}'] = np.percentile(latencies, 99) if latencies else 0.0
                result[f'latency_std_{label}'] = np.std(latencies) if latencies else 0.0
                result[f'latency_cv_{label}'] = result[f'latency_std_{label}'] / (result[f'avg_latency_{label}'] + 0.001)
                # Тренд за 24 часа (линейная регрессия)
                if len(rows) >= 2:
                    times = [datetime.fromisoformat(r[0]).timestamp() for r in rows]
                    vals = [r[1] if r[0] == 1 and r[1] > 0 else np.nan for r in rows]
                    valid = [(t, v) for t, v in zip(times, vals) if not np.isnan(v)]
                    if len(valid) >= 2:
                        ts, vs = zip(*valid)
                        slope = np.polyfit(ts, vs, 1)[0]
                        result[f'latency_trend_{label}'] = slope
                    else:
                        result[f'latency_trend_{label}'] = 0.0
                else:
                    result[f'latency_trend_{label}'] = 0.0
                # Частота проверок (интервалы)
                if len(rows) >= 2:
                    timestamps = sorted([datetime.fromisoformat(r[0]) for r in rows])
                    intervals = [(timestamps[i] - timestamps[i-1]).total_seconds()/60 for i in range(1, len(timestamps))]
                    result['check_interval_avg'] = np.mean(intervals) if intervals else 0
                else:
                    result['check_interval_avg'] = 0
        return result

    def _get_profile_history(self, profile_key: str, limit=100) -> List[Dict]:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sni_used, host_used, path_used FROM probe_history
            WHERE profile_key = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (profile_key, limit))
        rows = cursor.fetchall()
        return [{'sni_used': r[0], 'host_used': r[1], 'path_used': r[2]} for r in rows]

    def _compute_ip_stats(self, ip: str, exclude_key: str) -> Dict:
        conn = self._get_conn()
        cursor = conn.cursor()
        # Найти все профили на этом IP
        cursor.execute('''
            SELECT profile_key FROM profile_features
            WHERE profile_key LIKE ? AND profile_key != ?
        ''', (f'%{ip}%', exclude_key))
        keys = [r[0] for r in cursor.fetchall()]
        if not keys:
            return {'count': 0, 'success_rate': 0.0}
        # Статистика успешности за последний час
        cutoff = (datetime.now() - timedelta(hours=1)).isoformat()
        placeholders = ','.join(['?'] * len(keys))
        cursor.execute(f'''
            SELECT success FROM probe_history
            WHERE profile_key IN ({placeholders}) AND timestamp > ?
        ''', keys + [cutoff])
        rows = cursor.fetchall()
        if not rows:
            return {'count': len(keys), 'success_rate': 0.0}
        success_count = sum(1 for r in rows if r[0] == 1)
        return {'count': len(keys), 'success_rate': success_count / len(rows)}

    def _count_same_sni(self, sni: str, exclude_key: str) -> int:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(DISTINCT profile_key) FROM probe_history
            WHERE sni_used = ? AND profile_key != ?
        ''', (sni, exclude_key))
        return cursor.fetchone()[0]

    def update_features_db(self, features: Dict):
        conn = self._get_conn()
        cursor = conn.cursor()
        # Используем INSERT OR REPLACE
        columns = ', '.join(features.keys())
        placeholders = ', '.join(['?'] * len(features))
        cursor.execute(f'''
            INSERT OR REPLACE INTO profile_features ({columns})
            VALUES ({placeholders})
        ''', list(features.values()))
        conn.commit()
