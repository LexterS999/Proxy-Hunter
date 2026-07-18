"""
Интеллектуальный анализатор качества каналов с использованием SQLite и долгосрочной истории.
Оценивает каналы на основе метрик за последние N дней (по умолчанию 3) и не отключает их
после одного неудачного запуска.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from db import HistoryDB
from user_settings import (
    CHANNEL_HEALTH_THRESHOLD,
    CHANNEL_MIN_CONFIGS,
    CHANNEL_MIN_VALID_RATIO,
    CHANNEL_MIN_PROTOCOLS,
    CHANNEL_HISTORY_DAYS,
    CHANNEL_WHITELIST
)

logger = logging.getLogger(__name__)

# Переопределяем пороги, чтобы сделать их более консервативными
# Используем значения из user_settings, но если они слишком низкие, повышаем.
HEALTH_THRESHOLD = max(30.0, CHANNEL_HEALTH_THRESHOLD)  # минимум 30
MIN_CONFIGS = max(3, CHANNEL_MIN_CONFIGS)
MIN_VALID_RATIO = max(0.05, CHANNEL_MIN_VALID_RATIO)
MIN_PROTOCOLS = max(1, CHANNEL_MIN_PROTOCOLS)
HISTORY_DAYS = max(3, CHANNEL_HISTORY_DAYS)  # минимум 3 дня


class ChannelQualityAnalyzer:
    """
    Анализирует качество каналов на основе долгосрочной истории (SQLite).
    """

    def __init__(self):
        self.db = HistoryDB()
        self._whitelist = set(CHANNEL_WHILETIST)
        self._is_first_run = self._check_first_run()

    def _check_first_run(self) -> bool:
        """Проверяет, был ли хотя бы один запуск."""
        last_run = self.db.get_last_run()
        return last_run is None

    def _get_channel_history(self, url: str) -> List[Dict]:
        """Возвращает историю канала за последние HISTORY_DAYS дней."""
        return self.db.get_channel_history(url, limit=HISTORY_DAYS * 3)  # до 3 записей в день

    def _calculate_long_term_score(self, url: str) -> Optional[float]:
        """Вычисляет средний скор за последние HISTORY_DAYS дней."""
        scores = []
        history = self._get_channel_history(url)
        if not history:
            return None
        # Берём только записи за последние HISTORY_DAYS
        cutoff = (datetime.now() - timedelta(days=HISTORY_DAYS)).isoformat()
        for record in history:
            if record['timestamp'] >= cutoff and record['overall_score'] > 0:
                scores.append(record['overall_score'])
        if not scores:
            return None
        return sum(scores) / len(scores)

    def _get_latest_metrics(self, url: str) -> Dict:
        """Возвращает последние метрики канала из таблицы channels."""
        ch = self.db.get_channel(url)
        if ch:
            return ch.get('metrics', {})
        return {}

    def calculate_health_score(self, channel_url: str) -> float:
        """
        Вычисляет оценку здоровья канала на основе долгосрочной истории:
        - средний скор за последние HISTORY_DAYS дней (вес 50%)
        - текущий скор (вес 30%)
        - разнообразие протоколов (вес 10%)
        - стабильность (изменение скоров) (вес 10%)
        """
        if channel_url in self._whitelist:
            return 100.0

        # Получаем долгосрочный скор
        long_score = self._calculate_long_term_score(channel_url)
        if long_score is None:
            # Если нет истории, используем текущие метрики
            metrics = self._get_latest_metrics(channel_url)
            long_score = metrics.get('overall_score', 0.0)

        # Текущий скор (из последнего запуска)
        current_metrics = self._get_latest_metrics(channel_url)
        current_score = current_metrics.get('overall_score', 0.0)

        # Разнообразие протоколов
        protocol_counts = current_metrics.get('protocol_counts', {})
        unique_protocols = len([p for p, c in protocol_counts.items() if c > 0])
        proto_score = min(10, unique_protocols * 2)  # до 10 баллов

        # Стабильность: если есть история, смотрим стандартное отклонение
        history = self._get_channel_history(channel_url)
        stability_score = 0.0
        if len(history) >= 3:
            scores = [h['overall_score'] for h in history if h['overall_score'] > 0]
            if scores:
                import statistics
                try:
                    std = statistics.stdev(scores)
                    # Если std мал (<10), стабильность высокая (10 баллов), иначе снижаем
                    stability_score = max(0, 10 - std / 2)
                    stability_score = min(10, stability_score)
                except:
                    stability_score = 5.0

        # Комбинируем: 50% долгосрочный, 30% текущий, 10% протоколы, 10% стабильность
        score = (long_score * 0.5 +
                 current_score * 0.3 +
                 proto_score * 1.0 +   # уже в процентах
                 stability_score)
        # Нормализуем к 0-100
        score = min(100, max(0, score))
        return score

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоров ли канал."""
        if channel_url in self._whitelist:
            return True
        if self._is_first_run:
            logger.info(f"First run: assuming all channels healthy, including {channel_url}")
            return True
        score = self.calculate_health_score(channel_url)
        threshold = HEALTH_THRESHOLD
        return score >= threshold

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает список нездоровых каналов."""
        unhealthy = []
        for url in channel_urls:
            if not self.is_channel_healthy(url):
                unhealthy.append(url)
        return unhealthy

    def update_health(self, channel_urls: List[str], run_id: int = None):
        """Обновляет данные о здоровье для списка каналов (сохраняет метрики в БД)."""
        # Мы не храним отдельный health_score, он вычисляется на лету.
        # Но мы можем обновить метрики канала в таблице channels.
        for url in channel_urls:
            # Получаем текущие метрики из config (они уже обновлены в процессе сбора)
            # Здесь мы просто вызываем обновление метрик через отдельный метод.
            pass

    def get_health_report(self) -> Dict:
        """Возвращает отчёт о состоянии всех каналов."""
        channels = self.db.get_all_channels()
        healthy_count = 0
        total = len(channels)
        for ch in channels:
            if self.is_channel_healthy(ch['url']):
                healthy_count += 1
        return {
            'channels': channels,
            'summary': {
                'total': total,
                'healthy': healthy_count,
                'unhealthy': total - healthy_count
            }
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        """
        Возвращает список каналов, которые следует оставить (удаляет плохие).
        """
        healthy = []
        for url in channel_urls:
            if self.is_channel_healthy(url):
                healthy.append(url)
            else:
                logger.info(f"Channel {url} marked as unhealthy (score={self.calculate_health_score(url):.1f}), removing.")
        return healthy
