"""
Кластеризация каналов по поведенческим паттернам.
"""

import logging
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Optional

from user_settings import CLUSTERING_ENABLED, CLUSTER_COUNT, CLUSTER_FEATURES

logger = logging.getLogger(__name__)


class ChannelClustering:
    """
    Группирует каналы на основе их поведенческих метрик.
    Определяет типы: «золотые», «волатильные», «специализированные», «слабые».
    """

    def __init__(self, n_clusters: int = CLUSTER_COUNT, random_state: int = 42):
        self.n_clusters = n_clusters
        self.random_state = random_state
        self.kmeans: Optional[KMeans] = None
        self.scaler = StandardScaler()
        self.cluster_profiles: Dict[int, Dict] = {}
        self._enabled = CLUSTERING_ENABLED
        self._fitted = False

    def fit(self, channels_data: List[Dict]) -> None:
        """
        Обучает модель кластеризации на исторических данных каналов.
        Ожидает список словарей с ключами, перечисленными в CLUSTER_FEATURES.
        """
        if not self._enabled or len(channels_data) < 2:
            logger.debug("Clustering disabled or insufficient data (need at least 2 samples)")
            return

        features = self._extract_features(channels_data)
        if features is None or len(features) < 2:
            logger.warning("Not enough valid data for clustering")
            return

        # Определяем фактическое число кластеров, не превышающее количество уникальных образцов
        # и не превышающее количество образцов
        n_samples = len(features)
        # Удаляем дубликаты, чтобы избежать предупреждения sklearn
        unique_features = np.unique(features, axis=0)
        n_unique = len(unique_features)
        actual_clusters = min(self.n_clusters, n_unique, n_samples)
        if actual_clusters < 1:
            actual_clusters = 1

        scaled = self.scaler.fit_transform(features)
        self.kmeans = KMeans(n_clusters=actual_clusters, random_state=self.random_state, n_init=10)
        self.kmeans.fit(scaled)
        self._fitted = True

        # Строим профили кластеров
        labels = self.kmeans.labels_
        for i in range(actual_clusters):
            mask = labels == i
            cluster_indices = [j for j, m in enumerate(mask) if m]
            if not cluster_indices:
                continue
            cluster_data = [channels_data[j] for j in cluster_indices]
            profile = self._build_profile(cluster_data)
            profile['size'] = len(cluster_data)
            profile['name'] = self._name_cluster(profile)
            self.cluster_profiles[i] = profile

        logger.info(f"Clustering completed: {len(self.cluster_profiles)} clusters (requested {self.n_clusters})")

    def predict(self, channel_data: Dict) -> int:
        """
        Определяет кластер для нового канала.
        Возвращает -1 если кластеризация не обучена или отключена.
        """
        if not self._fitted or not self._enabled:
            return -1

        features = self._extract_features([channel_data])
        if features is None:
            return -1

        scaled = self.scaler.transform(features)
        cluster_id = self.kmeans.predict(scaled)[0]
        return int(cluster_id)  # гарантируем int, а не numpy.int64

    def get_cluster_profile(self, cluster_id: int) -> Dict:
        """Возвращает профиль кластера."""
        return self.cluster_profiles.get(cluster_id, {})

    def _extract_features(self, data_list: List[Dict]) -> Optional[np.ndarray]:
        """Извлекает признаки для кластеризации."""
        if not data_list:
            return None

        features = []
        for d in data_list:
            row = []
            for feat in CLUSTER_FEATURES:
                val = d.get(feat, 0)
                if val is None:
                    val = 0
                row.append(float(val))
            features.append(row)

        if not features:
            return None
        return np.array(features)

    def _build_profile(self, cluster_data: List[Dict]) -> Dict:
        """Строит статистический профиль кластера."""
        if not cluster_data:
            return {}

        scores = [d.get('overall_score', 0) for d in cluster_data if d.get('overall_score') is not None]
        configs = [d.get('total_configs', 0) for d in cluster_data if d.get('total_configs') is not None]
        success_rates = []
        for d in cluster_data:
            total = d.get('total_configs', 0)
            valid = d.get('valid_configs', 0)
            if total > 0:
                success_rates.append(valid / total)

        volatilities = [d.get('config_volatility', 0) for d in cluster_data if d.get('config_volatility') is not None]

        profile = {
            'avg_score': float(np.mean(scores)) if scores else 0.0,
            'avg_configs': float(np.mean(configs)) if configs else 0.0,
            'avg_success_rate': float(np.mean(success_rates)) if success_rates else 0.0,
            'avg_volatility': float(np.mean(volatilities)) if volatilities else 0.0,
            'size': len(cluster_data),
        }
        return profile

    def _name_cluster(self, profile: Dict) -> str:
        """Присваивает имя кластеру на основе профиля."""
        avg_score = profile.get('avg_score', 0)
        avg_configs = profile.get('avg_configs', 0)
        volatility = profile.get('avg_volatility', 0)

        if avg_score > 70 and avg_configs > 20 and volatility < 0.3:
            return 'golden'
        elif avg_score > 50 and volatility > 0.4:
            return 'volatile'
        elif avg_score > 60 and avg_configs < 10:
            return 'specialized'
        else:
            return 'weak'
