"""
Интеллектуальный анализатор качества каналов (v2) с расширенными метриками,
адаптивными порогами, кластеризацией и ансамблевой моделью.
Интегрирует все новые компоненты.
"""

import json
import logging
import os
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque

from user_settings import (
    CHANNEL_HEALTH_THRESHOLD,
    CHANNEL_MIN_CONFIGS,
    CHANNEL_MIN_VALID_RATIO,
    CHANNEL_MIN_PROTOCOLS,
    CHANNEL_HISTORY_DAYS,
    CHANNEL_WHITELIST,
    ADAPTIVE_THRESHOLDS_ENABLED,
    GRACEFUL_REMOVAL_ENABLED,
    AB_TEST_ENABLED
)

from channel_metrics_v2 import ChannelMetricsV2
from adaptive_thresholds import AdaptiveThresholds
from channel_clustering import ChannelClustering
from channel_health_model import EnsembleHealthModel

logger = logging.getLogger(__name__)


class GracefulRemoval:
    """
    Реализует мягкое удаление: каналы с пограничным здоровьем помещаются под наблюдение
    на несколько циклов перед окончательным удалением.
    """

    def __init__(self, watch_period: int = 3):
        self.watch_period = watch_period
        self.watch_list: Dict[str, int] = {}  # channel_url -> remaining cycles

    def process(self, channel_url: str, health_result: Dict) -> bool:
        """
        Возвращает True, если канал следует оставить.
        """
        health_score = health_result.get('health_score', 0)
        recommendation = health_result.get('recommendation', 'keep')

        if recommendation == 'keep' or health_score >= 50:
            # Здоров — удаляем из watch list
            self.watch_list.pop(channel_url, None)
            return True

        if health_score >= 30 and recommendation == 'watch':
            # Пограничный — помещаем под наблюдение
            if channel_url not in self.watch_list:
                self.watch_list[channel_url] = self.watch_period
                return True
            else:
                self.watch_list[channel_url] -= 1
                if self.watch_list[channel_url] <= 0:
                    # Время истекло — удаляем
                    return False
                return True

        # Низкий скор или рекомендация удалить
        return False


class ChannelABTest:
    """
    Периодически включает отключённые каналы для проверки восстановления.
    """

    def __init__(self, test_interval: int = 5, test_batch_size: int = 3):
        self.test_interval = test_interval
        self.test_batch_size = test_batch_size
        self.counter = 0

    def get_test_channels(self, disabled_channels: List[str]) -> List[str]:
        """Возвращает список каналов для тестирования в этом цикле."""
        if not disabled_channels:
            return []
        self.counter += 1
        if self.counter % self.test_interval == 0:
            # Берём первые test_batch_size каналов
            return disabled_channels[:self.test_batch_size]
        return []

    def process_results(self, test_results: Dict[str, Dict]) -> List[str]:
        """
        Обрабатывает результаты тестов. Возвращает список каналов, которые восстановились
        и должны быть повторно включены.
        """
        reenabled = []
        for url, result in test_results.items():
            if result.get('health_score', 0) > 40 and result.get('recommendation') != 'remove':
                reenabled.append(url)
        return reenabled


class ChannelQualityAnalyzer:
    """
    Основной анализатор качества каналов (v2).
    Использует расширенные метрики, адаптивные пороги, кластеризацию и ансамблевую модель.
    """

    def __init__(self, history_file: str = 'configs/channel_stats.json',
                 health_file: str = 'configs/channel_health.json'):
        self.history_file = history_file
        self.health_file = health_file
        self.history = self._load_history()
        self.health_data = self._load_health()
        self._whitelist = set(CHANNEL_WHITELIST)
        # Количество выполненных запусков (runs) из истории
        self._run_count = len(self.history.get('runs', []))
        # Флаг первого запуска: считаем, что это первый запуск, если запусков меньше 2
        self._is_first_run = self._run_count < 2

        # Новые компоненты
        self.adaptive_thresholds = AdaptiveThresholds()
        self.clustering = ChannelClustering()
        self.health_model = EnsembleHealthModel()
        self.graceful_removal = GracefulRemoval() if GRACEFUL_REMOVAL_ENABLED else None
        self.ab_test = ChannelABTest() if AB_TEST_ENABLED else None

        # Кеш метрик для каналов
        self._metrics_cache: Dict[str, ChannelMetricsV2] = {}

    def _load_history(self) -> Dict:
        """Загружает историю каналов из channel_stats.json."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data
            except Exception as e:
                logger.warning(f"Failed to load channel history: {e}")
        return {}

    def _load_health(self) -> Dict:
        """Загружает сохранённые данные о здоровье каналов."""
        if os.path.exists(self.health_file):
            try:
                with open(self.health_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'channels' not in data:
                        data['channels'] = {}
                    if 'last_updated' not in data:
                        data['last_updated'] = datetime.now().isoformat()
                    return data
            except Exception as e:
                logger.warning(f"Failed to load health data: {e}")
        return {'channels': {}, 'last_updated': datetime.now().isoformat()}

    def _convert_to_serializable(self, obj):
        """
        Рекурсивно преобразует все numpy-типы и другие несериализуемые объекты
        в стандартные Python-типы для JSON.
        """
        # Обрабатываем numpy скаляры
        if isinstance(obj, np.generic):
            return obj.item()
        # Явно обрабатываем numpy.bool_ (отдельно на всякий случай)
        if isinstance(obj, np.bool_):
            return bool(obj)
        if isinstance(obj, dict):
            return {k: self._convert_to_serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._convert_to_serializable(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self._convert_to_serializable(v) for v in obj)
        if isinstance(obj, set):
            return [self._convert_to_serializable(v) for v in obj]
        # Если это bool или другие стандартные типы, возвращаем как есть
        return obj

    def _save_health(self):
        """Сохраняет данные о здоровье каналов с преобразованием NumPy-типов."""
        self.health_data['last_updated'] = datetime.now().isoformat()
        try:
            os.makedirs(os.path.dirname(self.health_file), exist_ok=True)
            serializable_data = self._convert_to_serializable(self.health_data)
            with open(self.health_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save health data: {e}")

    def _get_channel_history(self, channel_url: str) -> List[Dict]:
        """Извлекает историю для конкретного канала."""
        channels = self.history.get('channels', [])
        for ch in channels:
            if ch.get('url') == channel_url:
                return [ch.get('metrics', {})]
        return []

    def _extract_current_metrics(self, channel_url: str) -> Dict:
        """Извлекает текущие метрики канала из истории."""
        channels = self.history.get('channels', [])
        for ch in channels:
            if ch.get('url') == channel_url:
                metrics = ch.get('metrics', {})
                return metrics
        return {}

    def _calculate_derived_metrics(self, history: List[Dict]) -> Dict:
        """Рассчитывает производные метрики на основе истории."""
        if not history:
            return {}

        scores = [h.get('overall_score', 0) for h in history if h.get('overall_score') is not None]
        configs = [h.get('total_configs', 0) for h in history if h.get('total_configs') is not None]
        valids = [h.get('valid_configs', 0) for h in history if h.get('valid_configs') is not None]
        latencies = [h.get('avg_response_time', 0) for h in history if h.get('avg_response_time', 0) > 0]

        score_trend = ChannelMetricsV2.calculate_trend(scores) if scores else 0.0
        config_trend = ChannelMetricsV2.calculate_trend(configs) if configs else 0.0
        valid_trend = ChannelMetricsV2.calculate_trend(valids) if valids else 0.0
        latency_trend = ChannelMetricsV2.calculate_trend(latencies) if latencies else 0.0

        score_vol = ChannelMetricsV2.calculate_volatility(scores) if scores else 0.0
        config_vol = ChannelMetricsV2.calculate_volatility(configs) if configs else 0.0

        expected_score = scores[-1] + score_trend if scores else 50.0
        expected_configs = configs[-1] + config_trend if configs else 0.0

        protocol_quality = 0.5

        return {
            'score_trend': score_trend,
            'config_trend': config_trend,
            'valid_trend': valid_trend,
            'latency_trend': latency_trend,
            'score_volatility': score_vol,
            'config_volatility': config_vol,
            'expected_score': expected_score,
            'expected_configs': expected_configs,
            'protocol_quality': protocol_quality,
        }

    def calculate_health_score(self, channel_url: str) -> float:
        """
        Вычисляет комплексный показатель здоровья канала.
        Использует ансамблевую модель, если доступна, иначе упрощённую формулу.
        """
        if channel_url in self._whitelist:
            return 100.0

        metrics = self._extract_current_metrics(channel_url)
        if not metrics:
            # Нет никаких данных — считаем нейтральным (не unhealthy)
            return 60.0

        total = metrics.get('total_configs', 0)
        valid = metrics.get('valid_configs', 0)
        overall_score = metrics.get('overall_score', 0)
        last_success = metrics.get('last_success')
        protocol_counts = metrics.get('protocol_counts', {})
        unique_protocols = len([p for p, c in protocol_counts.items() if c > 0])

        # Если канал никогда не давал конфигов, даём ему шанс
        if total == 0 and not last_success:
            return 60.0

        history = self._get_channel_history(channel_url)
        derived = self._calculate_derived_metrics(history)
        current_metrics = {**metrics, **derived}

        score = 0.0

        min_cfg = self.adaptive_thresholds.get_thresholds().get('min_configs', CHANNEL_MIN_CONFIGS)
        config_score = min(30, (total / min_cfg) * 30 if min_cfg > 0 else 0)
        score += config_score

        if total > 0:
            ratio = valid / total
            min_ratio = self.adaptive_thresholds.get_thresholds().get('min_valid_rate', CHANNEL_MIN_VALID_RATIO)
            ratio_score = min(30, (ratio / min_ratio) * 30 if min_ratio > 0 else 0)
            score += ratio_score

        min_protos = CHANNEL_MIN_PROTOCOLS
        proto_score = min(20, (unique_protocols / min_protos) * 20 if min_protos > 0 else 0)
        score += proto_score

        score_score = min(20, (overall_score / 50) * 20 if overall_score > 0 else 0)
        score += score_score

        if last_success:
            try:
                last_time = datetime.fromisoformat(last_success)
                age = (datetime.now() - last_time).total_seconds() / 3600
                if age < 24:
                    score += 10
                elif age < 72:
                    score += 5
            except:
                pass
        else:
            score -= 10

        score_trend = derived.get('score_trend', 0)
        if score_trend < -0.3:
            score -= 10
        elif score_trend > 0.3:
            score += 5

        config_vol = derived.get('config_volatility', 0)
        if config_vol > 0.8:
            score -= 10
        elif config_vol > 0.5:
            score -= 5

        return max(0, min(100, score))

    def is_channel_healthy(self, channel_url: str) -> bool:
        if channel_url in self._whitelist:
            return True
        # Если это первый запуск или запусков меньше 2, считаем все каналы здоровыми
        if self._is_first_run:
            return True

        score = self.calculate_health_score(channel_url)
        threshold = self.adaptive_thresholds.get_thresholds().get('base_health', CHANNEL_HEALTH_THRESHOLD)
        return score >= threshold

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        unhealthy = []
        for url in channel_urls:
            if not self.is_channel_healthy(url):
                unhealthy.append(url)
        return unhealthy

    def update_health(self, channel_urls: List[str], history_data: Optional[Dict] = None):
        """
        Обновляет данные о здоровье для списка каналов.
        Если передан history_data, использует его, иначе читает с диска.
        """
        if history_data is not None:
            self.history = history_data
        else:
            self.history = self._load_history()

        # Обновляем количество запусков
        self._run_count = len(self.history.get('runs', []))
        self._is_first_run = self._run_count < 2

        all_channel_data = []
        for url in channel_urls:
            metrics = self._extract_current_metrics(url)
            derived = self._calculate_derived_metrics(self._get_channel_history(url))
            combined = {**metrics, **derived}
            combined['url'] = url
            all_channel_data.append(combined)

        self.adaptive_thresholds.update(all_channel_data)

        # Обучаем кластеризацию только если данных достаточно
        if len(all_channel_data) > 1:
            self.clustering.fit(all_channel_data)
        else:
            logger.debug("Skipping clustering: not enough data")

        for url in channel_urls:
            metrics = self._extract_current_metrics(url)
            derived = self._calculate_derived_metrics(self._get_channel_history(url))
            current_metrics = {**metrics, **derived}

            cluster_id = self.clustering.predict(current_metrics)
            score = self.calculate_health_score(url)

            # Приводим порог к float
            threshold = float(self.adaptive_thresholds.get_thresholds().get('base_health', CHANNEL_HEALTH_THRESHOLD))
            is_healthy = score >= threshold

            self.health_data['channels'][url] = {
                'health_score': float(score),
                'last_checked': datetime.now().isoformat(),
                'is_healthy': bool(is_healthy),   # явно приводим к bool
                'cluster': int(cluster_id) if cluster_id != -1 else -1,
                'metrics_summary': {
                    'total_configs': int(metrics.get('total_configs', 0)),
                    'valid_configs': int(metrics.get('valid_configs', 0)),
                    'overall_score': float(metrics.get('overall_score', 0)),
                    'score_trend': float(derived.get('score_trend', 0)),
                    'config_volatility': float(derived.get('config_volatility', 0)),
                }
            }

        self._save_health()

    def get_health_report(self) -> Dict:
        """Возвращает детальный отчёт о здоровье каналов."""
        channels = self.health_data.get('channels', {})
        total = len(channels)
        healthy = sum(1 for c in channels.values() if c.get('is_healthy', False))
        unhealthy = total - healthy

        cluster_dist = defaultdict(int)
        for c in channels.values():
            cluster_id = c.get('cluster', -1)
            if cluster_id != -1:
                cluster_dist[cluster_id] += 1

        watch_list = []
        if self.graceful_removal:
            watch_list = list(self.graceful_removal.watch_list.keys())

        # Приводим пороги к сериализуемому виду
        thresholds = self._convert_to_serializable(self.adaptive_thresholds.get_thresholds())

        return {
            'channels': channels,
            'last_updated': self.health_data.get('last_updated'),
            'summary': {
                'total': total,
                'healthy': healthy,
                'unhealthy': unhealthy,
                'cluster_distribution': dict(cluster_dist),
                'watch_list': watch_list,
                'thresholds': thresholds,
            }
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        """
        Применяет все стратегии (graceful removal, AB-тестирование) и возвращает
        список каналов, которые следует оставить.
        """
        if self._is_first_run:
            return channel_urls

        healthy_urls = []
        watch_urls = []

        for url in channel_urls:
            if url in self._whitelist:
                healthy_urls.append(url)
                continue

            health_info = self.health_data.get('channels', {}).get(url, {})
            health_score = health_info.get('health_score', 50)
            is_healthy = health_info.get('is_healthy', True)

            if is_healthy or health_score >= 50:
                healthy_urls.append(url)
            elif health_score >= 30:
                if self.graceful_removal:
                    if self.graceful_removal.process(url, {'health_score': health_score, 'recommendation': 'watch'}):
                        watch_urls.append(url)
                else:
                    watch_urls.append(url)

        disabled = [u for u in channel_urls if u not in healthy_urls and u not in watch_urls]
        if self.ab_test:
            test_candidates = self.ab_test.get_test_channels(disabled)
            if test_candidates:
                healthy_urls.extend(test_candidates)

        return list(set(healthy_urls + watch_urls))
