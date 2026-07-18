"""
Расширенные метрики каналов для глубокого анализа.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, List
import numpy as np


@dataclass
class ChannelMetricsV2:
    """Расширенный набор метрик для анализа качества канала."""
    # Существующие базовые метрики
    total_configs: int = 0
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    # Новые метрики
    total_parsed: int = 0                     # Всего спарсено до валидации
    parse_success_rate: float = 0.0           # valid / total_parsed
    protocol_diversity: float = 0.0           # Индекс Шеннона
    response_time_std: float = 0.0            # Стандартное отклонение времени ответа
    response_time_p50: float = 0.0            # Медиана
    response_time_p95: float = 0.0            # 95-й перцентиль
    config_age_avg: float = 0.0               # Средний возраст конфигов (часы)
    update_frequency: float = 0.0             # Обновлений в день
    first_seen: Optional[datetime] = None
    last_parsed: Optional[datetime] = None
    consecutive_failures: int = 0             # Количество неудач подряд

    # Производные метрики (рассчитываются на основе истории)
    config_trend: float = 0.0                 # Наклон тренда total_configs
    valid_trend: float = 0.0                  # Наклон тренда valid_configs
    score_trend: float = 0.0                  # Наклон тренда overall_score
    latency_trend: float = 0.0                # Наклон тренда avg_response_time
    config_volatility: float = 0.0            # CV total_configs
    score_volatility: float = 0.0             # CV overall_score
    expected_configs: float = 0.0             # Прогноз следующего значения
    expected_score: float = 0.0               # Прогноз следующего скора
    protocol_quality: float = 0.0             # Взвешенное качество протоколов

    # Дополнительные поля для кластеризации и принятия решений
    cluster_id: int = -1
    health_score: float = 50.0
    health_confidence: float = 0.0
    days_left: Optional[float] = None
    recommendation: str = 'keep'              # keep, watch, remove

    def to_dict(self) -> Dict:
        """Преобразует в словарь для сериализации."""
        result = {}
        for k, v in self.__dict__.items():
            if isinstance(v, datetime):
                result[k] = v.isoformat() if v else None
            elif isinstance(v, dict):
                result[k] = v
            else:
                result[k] = v
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> 'ChannelMetricsV2':
        """Создаёт объект из словаря."""
        # Преобразуем datetime поля
        for field_name in ['first_seen', 'last_parsed']:
            if field_name in data and data[field_name]:
                data[field_name] = datetime.fromisoformat(data[field_name])
        return cls(**data)

    @staticmethod
    def calculate_protocol_diversity(protocol_counts: Dict[str, int]) -> float:
        """Рассчитывает индекс Шеннона для разнообразия протоколов."""
        total = sum(protocol_counts.values())
        if total == 0:
            return 0.0
        probs = [count / total for count in protocol_counts.values() if count > 0]
        if not probs:
            return 0.0
        # Индекс Шеннона: -sum(p * log(p))
        shannon = -sum(p * np.log(p) for p in probs)
        # Нормализуем на max (log(k)) где k - число протоколов
        max_shannon = np.log(len(probs)) if len(probs) > 1 else 1.0
        return shannon / max_shannon if max_shannon > 0 else 0.0

    @staticmethod
    def calculate_trend(values: List[float]) -> float:
        """Рассчитывает нормализованный тренд методом наименьших квадратов."""
        if len(values) < 2:
            return 0.0
        x = np.arange(len(values))
        slope = np.polyfit(x, values, 1)[0]
        mean = np.mean(values) if values else 1.0
        if mean == 0:
            return 0.0
        return slope / mean

    @staticmethod
    def calculate_volatility(values: List[float]) -> float:
        """Рассчитывает коэффициент вариации."""
        if len(values) < 2:
            return 0.0
        mean = np.mean(values)
        if mean == 0:
            return 0.0
        std = np.std(values)
        return std / mean

    @staticmethod
    def calculate_quantiles(values: List[float], quantiles: List[float]) -> List[float]:
        """Рассчитывает перцентили."""
        if not values:
            return [0.0] * len(quantiles)
        return [np.percentile(values, q * 100) for q in quantiles]
