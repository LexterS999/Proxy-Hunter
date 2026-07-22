import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple

import numpy as np

from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)


class FeatureExtractor:
    def __init__(self, db_path='configs/history.db'):
        self.db_path = db_path
        self._conn = None
        self._stats_cache: Dict[str, Dict] = {}
        self._history_cache: Dict[str, List[Dict]] = {}
        self._ip_stats_cache: Dict[Tuple[str, str], Dict] = {}
        self._sni_count_cache: Dict[Tuple[str, str], int] = {}

    def _get_conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self._conn

    def get_profile_key(self, config: str) -> Optional[str]:
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
        server = parsed.get('address') or parsed.get('add') or ''
        sni = parsed.get('sni', '')
        host = parsed.get('host', '')
        path = parsed.get('path', '')

        features = {
            'profile_key': profile_key,
            'server': server,
            'port': int(parsed.get('port', 0) or 0),
            'protocol': parsed.get('protocol', config.split('://')[0].lower() if '://' in config else 'unknown'),
            'transport': parsed.get('type', parsed.get('net', 'tcp')),
            'sni': sni,
            'host': host,
            'path': path,
            'has_sni': 1 if sni else 0,
            'has_host': 1 if host else 0,
            'has_path': 1 if path else 0,
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

        history = self._get_profile_history(profile_key)
        if history:
            features['sni_count'] = len({rec['sni_used'] for rec in history if rec.get('sni_used')})
            features['host_count'] = len({rec['host_used'] for rec in history if rec.get('host_used')})
            features['path_count'] = len({rec['path_used'] for rec in history if rec.get('path_used')})

        features.update(self._compute_stats(profile_key))

        if server:
            ip_stats = self._compute_ip_stats(server, profile_key)
            features['same_ip_count'] = ip_stats['count']
            features['same_ip_success_rate'] = ip_stats['success_rate']
        if sni:
            features['same_sni_count'] = self._count_same_sni(sni, profile_key)

        return features

    def _fetch_probe_rows(self, profile_key: str, hours: int = 168) -> List[Tuple[str, int, float, str, str, str]]:
        conn = self._get_conn()
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        try:
            cursor.execute(
                '''
                SELECT timestamp, success, latency, sni_used, host_used, path_used
                FROM probe_history
                WHERE profile_key = ? AND timestamp > ?
                ORDER BY timestamp ASC
                ''',
                (profile_key, cutoff),
            )
            return cursor.fetchall()
        except sqlite3.OperationalError:
            return []

    def _compute_stats(self, profile_key: str) -> Dict:
        if profile_key in self._stats_cache:
            return self._stats_cache[profile_key]

        rows = self._fetch_probe_rows(profile_key, hours=168)
        windows = {'1h': 1, '6h': 6, '24h': 24, '7d': 168}
        now = datetime.now()
        result: Dict[str, float] = {}

        parsed_rows = []
        for row in rows:
            try:
                ts = datetime.fromisoformat(row[0])
            except Exception:
                continue
            parsed_rows.append({
                'timestamp': ts,
                'success': int(row[1]),
                'latency': float(row[2] or 0.0),
                'sni_used': row[3],
                'host_used': row[4],
                'path_used': row[5],
            })

        for label, hours in windows.items():
            cutoff = now - timedelta(hours=hours)
            scoped = [r for r in parsed_rows if r['timestamp'] > cutoff]
            latencies = [r['latency'] for r in scoped if r['success'] == 1 and r['latency'] > 0]
            successes = sum(1 for r in scoped if r['success'] == 1)
            total = len(scoped)
            result[f'count_{label}'] = total
            result[f'success_{label}'] = successes
            result[f'avg_latency_{label}'] = float(np.mean(latencies)) if latencies else 0.0

            if label == '24h':
                result[f'p90_latency_{label}'] = float(np.percentile(latencies, 90)) if latencies else 0.0
                result[f'p99_latency_{label}'] = float(np.percentile(latencies, 99)) if latencies else 0.0
                result[f'latency_std_{label}'] = float(np.std(latencies)) if latencies else 0.0
                avg = result[f'avg_latency_{label}']
                result[f'latency_cv_{label}'] = result[f'latency_std_{label}'] / (avg + 0.001)

                valid = [(r['timestamp'].timestamp(), r['latency']) for r in scoped if r['success'] == 1 and r['latency'] > 0]
                if len(valid) >= 2:
                    ts, vs = zip(*valid)
                    result[f'latency_trend_{label}'] = float(np.polyfit(ts, vs, 1)[0])
                else:
                    result[f'latency_trend_{label}'] = 0.0

                if len(scoped) >= 2:
                    timestamps = [r['timestamp'] for r in scoped]
                    intervals = [
                        (timestamps[i] - timestamps[i - 1]).total_seconds() / 60.0
                        for i in range(1, len(timestamps))
                        if (timestamps[i] - timestamps[i - 1]).total_seconds() > 0
                    ]
                    result['check_interval_avg'] = float(np.mean(intervals)) if intervals else 0.0
                else:
                    result['check_interval_avg'] = 0.0

        self._stats_cache[profile_key] = result
        return result

    def _get_profile_history(self, profile_key: str, limit=100) -> List[Dict]:
        cache_key = f"{profile_key}:{limit}"
        if cache_key in self._history_cache:
            return self._history_cache[cache_key]

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute(
                '''
                SELECT sni_used, host_used, path_used FROM probe_history
                WHERE profile_key = ?
                ORDER BY timestamp DESC LIMIT ?
                ''',
                (profile_key, limit),
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            rows = []
        history = [{'sni_used': r[0], 'host_used': r[1], 'path_used': r[2]} for r in rows]
        self._history_cache[cache_key] = history
        return history

    def _compute_ip_stats(self, ip: str, exclude_key: str) -> Dict:
        cache_key = (ip, exclude_key)
        if cache_key in self._ip_stats_cache:
            return self._ip_stats_cache[cache_key]

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute(
                '''
                SELECT key FROM profiles
                WHERE server = ? AND key != ?
                ''',
                (ip, exclude_key),
            )
            keys = [r[0] for r in cursor.fetchall()]
        except sqlite3.OperationalError:
            keys = []

        if not keys:
            result = {'count': 0, 'success_rate': 0.0}
            self._ip_stats_cache[cache_key] = result
            return result

        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        placeholders = ','.join(['?'] * len(keys))
        try:
            cursor.execute(
                f'''
                SELECT success FROM probe_history
                WHERE profile_key IN ({placeholders}) AND timestamp > ?
                ''',
                keys + [cutoff],
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            rows = []

        if not rows:
            result = {'count': len(keys), 'success_rate': 0.0}
        else:
            success_count = sum(1 for r in rows if int(r[0]) == 1)
            result = {'count': len(keys), 'success_rate': success_count / len(rows)}
        self._ip_stats_cache[cache_key] = result
        return result

    def _count_same_sni(self, sni: str, exclude_key: str) -> int:
        cache_key = (sni, exclude_key)
        if cache_key in self._sni_count_cache:
            return self._sni_count_cache[cache_key]

        conn = self._get_conn()
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=7)).isoformat()
        try:
            cursor.execute(
                '''
                SELECT COUNT(DISTINCT profile_key) FROM probe_history
                WHERE sni_used = ? AND profile_key != ? AND timestamp > ?
                ''',
                (sni, exclude_key, cutoff),
            )
            count = int(cursor.fetchone()[0])
        except sqlite3.OperationalError:
            count = 0
        self._sni_count_cache[cache_key] = count
        return count

    def update_features_db(self, features: Dict):
        conn = self._get_conn()
        cursor = conn.cursor()
        columns = ', '.join(features.keys())
        placeholders = ', '.join(['?'] * len(features))
        cursor.execute(
            f'''
            INSERT OR REPLACE INTO profile_features ({columns})
            VALUES ({placeholders})
            ''',
            list(features.values()),
        )
        conn.commit()
