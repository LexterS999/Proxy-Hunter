import logging
from typing import List, Dict
from collections import defaultdict

logger = logging.getLogger(__name__)

class ChannelSelector:
    def __init__(self, db_path='configs/history.db'):
        self.db_path = db_path
        self._conn = None

    def _get_conn(self):
        if self._conn is None:
            import sqlite3
            self._conn = sqlite3.connect(self.db_path)
        return self._conn

    def compute_channel_features(self, channel_url: str) -> Dict:
        conn = self._get_conn()
        cursor = conn.cursor()
        # Предполагаем, что в таблице probe_history есть поле channel_url
        # Если нет, можно связать через таблицу каналов
        cursor.execute('''
            SELECT 
                COUNT(*) as total_probes,
                AVG(latency) as avg_lat,
                SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) as successes,
                COUNT(DISTINCT protocol) as protocol_diversity,
                COUNT(DISTINCT profile_key) as unique_profiles,
                MAX(timestamp) as last_update
            FROM probe_history
            WHERE channel_url = ?
        ''', (channel_url,))
        row = cursor.fetchone()
        if not row:
            return {
                'total_probes': 0,
                'avg_latency': 0,
                'success_rate': 0,
                'protocol_diversity': 0,
                'unique_profiles': 0,
                'freshness': 0
            }
        total = row[0] or 1
        return {
            'total_probes': total,
            'avg_latency': row[1] or 0,
            'success_rate': row[2] / total if total else 0,
            'protocol_diversity': row[3] or 0,
            'unique_profiles': row[4] or 0,
            'freshness': 1 if row[5] else 0
        }

    def score_channel(self, features: Dict) -> float:
        # Веса
        w_success = 0.4
        w_diversity = 0.2
        w_freshness = 0.2
        w_uniqueness = 0.15
        w_latency = 0.05

        score = (
            w_success * min(1, features['success_rate'] * 2) +
            w_diversity * min(1, features['protocol_diversity'] / 3) +
            w_freshness * features['freshness'] +
            w_uniqueness * min(1, features['unique_profiles'] / 10) +
            w_latency * max(0, 1 - features['avg_latency'] / 2000)
        )
        return min(1, score)

    def select_channels(self, channel_urls: List[str], min_score=0.3, max_channels=20) -> List[str]:
        scored = []
        for url in channel_urls:
            feats = self.compute_channel_features(url)
            score = self.score_channel(feats)
            scored.append((score, url))
        scored.sort(reverse=True)
        # Возвращаем только те, что выше порога, и не более max_channels
        result = [url for score, url in scored if score >= min_score][:max_channels]
        logger.info(f"Channel selection: {len(channel_urls)} → {len(result)} channels")
        return result
