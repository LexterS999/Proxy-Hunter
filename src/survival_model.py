"""
Модель выживания (Survival Analysis) для прокси-профилей.
Использует экспоненциальное затухание надёжности.

Score = base_quality * exp(-λ * hours_since_last_success)

λ (lambda) зависит от:
- Протокола: VLESS+Reality λ=0.02 (медленный распад),
             VMess λ=0.08 (быстрый), Trojan λ=0.12
- Канала-источника: надёжные каналы → меньший λ
- Географии сервера: EU λ=0.03, US λ=0.04, Asia λ=0.06
- Истории: больше успешных проверок → меньший λ

ИСПРАВЛЕНО:
- Заменяет статический score на динамическую модель распада
- Учитывает время с последнего успеха
- Учитывает историю проверок (серии успехов/неудач)
- Интегрируется с ProfileScorer для композитной оценки
"""

import math
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# Базовые коэффициенты распада (λ) по протоколам
# Чем меньше λ, тем медленнее профиль "протухает"
PROTOCOL_DECAY_RATES: Dict[str, float] = {
    'vless_reality': 0.02,    # Самый устойчивый
    'vless_tls_ws': 0.03,
    'vless_tls_grpc': 0.035,
    'vless_tcp_tls': 0.04,
    'hysteria2': 0.05,
    'tuic': 0.055,
    'vmess': 0.08,            # Быстро детектируется
    'trojan': 0.12,           # Самый нестабильный
    'shadowsocks': 0.15,
}

# Модификаторы λ по географии сервера
GEO_DECAY_MODIFIERS: Dict[str, float] = {
    'EU': 0.8,       # Европа — стабильнее
    'US': 0.9,
    'ASIA': 1.2,     # Азия — менее стабильно
    'RU': 1.5,       # РФ — высокая нагрузка ТСПУ
    'CN': 1.8,       # Китай — GFW
    'IR': 1.6,       # Иран — GFI
    'OTHER': 1.0,
}

# Модификаторы λ по надёжности канала
CHANNEL_RELIABILITY_MODIFIERS: Dict[str, float] = {
    'excellent': 0.7,   # score > 0.8
    'good': 0.85,       # score 0.6-0.8
    'average': 1.0,     # score 0.4-0.6
    'poor': 1.3,        # score 0.2-0.4
    'dead': 2.0,        # score < 0.2
}


@dataclass
class SurvivalState:
    """Состояние выживания профиля."""
    config_hash: str = ""
    base_quality: float = 50.0
    last_success_time: Optional[float] = None
    first_seen_time: Optional[float] = None
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    total_checks: int = 0
    total_successes: int = 0
    protocol: str = ""
    server_geo: str = "OTHER"
    channel_reliability: str = "average"
    current_score: float = 0.0
    decay_rate: float = 0.05
    is_alive: bool = True
    death_time: Optional[float] = None


@dataclass
class SurvivalPrediction:
    """Прогноз выживания."""
    config_hash: str = ""
    current_score: float = 0.0
    predicted_score_1h: float = 0.0
    predicted_score_6h: float = 0.0
    predicted_score_24h: float = 0.0
    predicted_score_72h: float = 0.0
    half_life_hours: float = 0.0
    probability_alive_24h: float = 0.0
    probability_alive_72h: float = 0.0
    decay_rate: float = 0.0
    confidence: float = 0.0


class SurvivalModel:
    """
    Модель выживания прокси-профилей.
    Использует экспоненциальное затухание с адаптивным λ.
    """

    def __init__(
        self,
        death_threshold: float = 5.0,
        min_checks_for_confidence: int = 3,
        success_streak_bonus: float = 0.1,
        failure_streak_penalty: float = 0.15,
    ):
        self.death_threshold = death_threshold
        self.min_checks_for_confidence = min_checks_for_confidence
        self.success_streak_bonus = success_streak_bonus
        self.failure_streak_penalty = failure_streak_penalty

        # Хранилище состояний
        self._states: Dict[str, SurvivalState] = {}

    def register_profile(
        self,
        config_hash: str,
        base_quality: float = 50.0,
        protocol: str = "",
        server_geo: str = "OTHER",
        channel_reliability: str = "average",
    ) -> SurvivalState:
        """Регистрирует новый профиль в модели."""
        now = time.time()
        state = SurvivalState(
            config_hash=config_hash,
            base_quality=base_quality,
            first_seen_time=now,
            last_success_time=now,
            protocol=protocol,
            server_geo=server_geo.upper(),
            channel_reliability=channel_reliability,
        )
        state.decay_rate = self._calculate_decay_rate(state)
        state.current_score = base_quality
        self._states[config_hash] = state
        return state

    def record_success(self, config_hash: str, quality: Optional[float] = None) -> None:
        """Записывает успешную проверку."""
        state = self._states.get(config_hash)
        if not state:
            return

        now = time.time()
        state.last_success_time = now
        state.consecutive_successes += 1
        state.consecutive_failures = 0
        state.total_checks += 1
        state.total_successes += 1
        state.is_alive = True
        state.death_time = None

        if quality is not None:
            # Экспоненциальное сглаживание base_quality
            alpha = 0.3
            state.base_quality = alpha * quality + (1 - alpha) * state.base_quality

        # Пересчёт decay rate (успехи снижают λ)
        state.decay_rate = self._calculate_decay_rate(state)
        state.current_score = self._compute_score(state, now)

    def record_failure(self, config_hash: str) -> None:
        """Записывает неудачную проверку."""
        state = self._states.get(config_hash)
        if not state:
            return

        state.consecutive_failures += 1
        state.consecutive_successes = 0
        state.total_checks += 1

        # Пересчёт decay rate (неудачи повышают λ)
        state.decay_rate = self._calculate_decay_rate(state)

        # Если серия неудач критическая — профиль мёртв
        if state.consecutive_failures >= 5:
            state.is_alive = False
            state.death_time = time.time()
            state.current_score = 0.0
        else:
            state.current_score = self._compute_score(state, time.time())

    def get_score(self, config_hash: str) -> float:
        """Возвращает текущий score профиля."""
        state = self._states.get(config_hash)
        if not state:
            return 0.0
        if not state.is_alive:
            return 0.0
        return self._compute_score(state, time.time())

    def get_state(self, config_hash: str) -> Optional[SurvivalState]:
        """Возвращает состояние профиля."""
        return self._states.get(config_hash)

    def predict(self, config_hash: str) -> Optional[SurvivalPrediction]:
        """
        Прогнозирует выживание профиля на 1/6/24/72 часа вперёд.
        """
        state = self._states.get(config_hash)
        if not state:
            return None

        now = time.time()
        current = self._compute_score(state, now)
        lam = state.decay_rate

        prediction = SurvivalPrediction(
            config_hash=config_hash,
            current_score=current,
            predicted_score_1h=current * math.exp(-lam * 1),
            predicted_score_6h=current * math.exp(-lam * 6),
            predicted_score_24h=current * math.exp(-lam * 24),
            predicted_score_72h=current * math.exp(-lam * 72),
            decay_rate=lam,
        )

        # Half-life: время, за которое score падает вдвое
        if lam > 0:
            prediction.half_life_hours = math.log(2) / lam
        else:
            prediction.half_life_hours = float('inf')

        # Вероятность выживания (score > death_threshold)
        if state.base_quality > 0:
            threshold_ratio = self.death_threshold / state.base_quality
            if threshold_ratio < 1:
                t_24 = -math.log(threshold_ratio) / lam if lam > 0 else float('inf')
                prediction.probability_alive_24h = min(1.0, t_24 / 24.0)
                t_72 = -math.log(threshold_ratio) / lam if lam > 0 else float('inf')
                prediction.probability_alive_72h = min(1.0, t_72 / 72.0)
            else:
                prediction.probability_alive_24h = 0.0
                prediction.probability_alive_72h = 0.0

        # Confidence на основе количества проверок
        if state.total_checks >= self.min_checks_for_confidence:
            prediction.confidence = min(
                1.0,
                state.total_checks / (self.min_checks_for_confidence * 3)
            )
        else:
            prediction.confidence = state.total_checks / self.min_checks_for_confidence * 0.5

        return prediction

    def get_alive_profiles(self, min_score: float = 10.0) -> List[str]:
        """Возвращает хеши живых профилей с score >= min_score."""
        now = time.time()
        alive = []
        for config_hash, state in self._states.items():
            if not state.is_alive:
                continue
            score = self._compute_score(state, now)
            if score >= min_score:
                alive.append(config_hash)
        return alive

    def get_dead_profiles(self) -> List[str]:
        """Возвращает хеши мёртвых профилей."""
        return [
            config_hash for config_hash, state in self._states.items()
            if not state.is_alive
        ]

    def cleanup_dead(self, max_age_hours: float = 168.0) -> int:
        """
        Удаляет мёртвые профили старше max_age_hours.
        Возвращает количество удалённых.
        """
        now = time.time()
        max_age_seconds = max_age_hours * 3600
        to_remove = []

        for config_hash, state in self._states.items():
            if not state.is_alive and state.death_time:
                if now - state.death_time > max_age_seconds:
                    to_remove.append(config_hash)

        for config_hash in to_remove:
            del self._states[config_hash]

        return len(to_remove)

    def get_stats(self) -> Dict[str, float]:
        """Возвращает статистику модели."""
        now = time.time()
        total = len(self._states)
        alive = sum(1 for s in self._states.values() if s.is_alive)
        dead = total - alive

        scores = [
            self._compute_score(s, now)
            for s in self._states.values()
            if s.is_alive
        ]

        return {
            'total_profiles': total,
            'alive': alive,
            'dead': dead,
            'avg_score': sum(scores) / len(scores) if scores else 0.0,
            'median_score': sorted(scores)[len(scores) // 2] if scores else 0.0,
            'avg_decay_rate': (
                sum(s.decay_rate for s in self._states.values()) / total
                if total > 0 else 0.0
            ),
        }

    # =========================================================================
    # Внутренние методы
    # =========================================================================
    def _calculate_decay_rate(self, state: SurvivalState) -> float:
        """
        Вычисляет адаптивный коэффициент распада λ.

        λ = base_λ(protocol) * geo_modifier * channel_modifier * streak_modifier
        """
        # Базовый λ по протоколу
        proto_key = self._get_protocol_key(state.protocol)
        base_lambda = PROTOCOL_DECAY_RATES.get(proto_key, 0.05)

        # Модификатор по географии
        geo_mod = GEO_DECAY_MODIFIERS.get(state.server_geo, 1.0)

        # Модификатор по надёжности канала
        channel_mod = CHANNEL_RELIABILITY_MODIFIERS.get(
            state.channel_reliability, 1.0
        )

        # Модификатор по серии успехов/неудач
        streak_mod = 1.0
        if state.consecutive_successes > 0:
            # Каждый успех снижает λ (профиль стабильнее)
            streak_mod = max(
                0.5,
                1.0 - state.consecutive_successes * self.success_streak_bonus
            )
        elif state.consecutive_failures > 0:
            # Каждая неудача повышает λ (профиль деградирует)
            streak_mod = min(
                3.0,
                1.0 + state.consecutive_failures * self.failure_streak_penalty
            )

        # Модификатор по общему количеству проверок
        # Больше данных → больше уверенность → меньше λ
        if state.total_checks > 10:
            confidence_mod = 0.8
        elif state.total_checks > 5:
            confidence_mod = 0.9
        else:
            confidence_mod = 1.0

        final_lambda = base_lambda * geo_mod * channel_mod * streak_mod * confidence_mod

        # Ограничиваем диапазон
        return max(0.005, min(0.5, final_lambda))

    def _compute_score(self, state: SurvivalState, now: float) -> float:
        """
        Вычисляет текущий score по формуле экспоненциального затухания.

        Score = base_quality * exp(-λ * hours_since_last_success)
        """
        if not state.is_alive:
            return 0.0

        if state.last_success_time is None:
            return state.base_quality * 0.5

        hours_elapsed = (now - state.last_success_time) / 3600.0

        if hours_elapsed < 0:
            hours_elapsed = 0.0

        score = state.base_quality * math.exp(-state.decay_rate * hours_elapsed)

        # Проверяем порог смерти
        if score < self.death_threshold:
            state.is_alive = False
            state.death_time = now
            return 0.0

        return round(max(0.0, min(100.0, score)), 2)

    @staticmethod
    def _get_protocol_key(protocol: str) -> str:
        """Нормализует ключ протокола."""
        proto = protocol.lower().strip()
        mapping = {
            'vless': 'vless_tcp_tls',
            'vless_reality': 'vless_reality',
            'vless_ws': 'vless_tls_ws',
            'vless_grpc': 'vless_tls_grpc',
            'vmess': 'vmess',
            'trojan': 'trojan',
            'shadowsocks': 'shadowsocks',
            'ss': 'shadowsocks',
            'hysteria2': 'hysteria2',
            'hy2': 'hysteria2',
            'tuic': 'tuic',
        }
        return mapping.get(proto, 'vless_tcp_tls')

    def bulk_update_scores(self) -> Dict[str, float]:
        """
        Массовый пересчёт всех score.
        Возвращает dict {config_hash: current_score}.
        """
        now = time.time()
        results = {}
        for config_hash, state in self._states.items():
            results[config_hash] = self._compute_score(state, now)
        return results

    def export_states(self) -> List[Dict]:
        """Экспортирует все состояния для сохранения в БД."""
        now = time.time()
        export = []
        for config_hash, state in self._states.items():
            export.append({
                'config_hash': config_hash,
                'base_quality': state.base_quality,
                'current_score': self._compute_score(state, now),
                'decay_rate': state.decay_rate,
                'is_alive': state.is_alive,
                'consecutive_successes': state.consecutive_successes,
                'consecutive_failures': state.consecutive_failures,
                'total_checks': state.total_checks,
                'total_successes': state.total_successes,
                'protocol': state.protocol,
                'server_geo': state.server_geo,
                'last_success_time': state.last_success_time,
                'first_seen_time': state.first_seen_time,
            })
        return export

    def import_states(self, states: List[Dict]) -> int:
        """Импортирует состояния из БД. Возвращает количество импортированных."""
        imported = 0
        for data in states:
            config_hash = data.get('config_hash', '')
            if not config_hash:
                continue
            state = SurvivalState(
                config_hash=config_hash,
                base_quality=data.get('base_quality', 50.0),
                last_success_time=data.get('last_success_time'),
                first_seen_time=data.get('first_seen_time'),
                consecutive_successes=data.get('consecutive_successes', 0),
                consecutive_failures=data.get('consecutive_failures', 0),
                total_checks=data.get('total_checks', 0),
                total_successes=data.get('total_successes', 0),
                protocol=data.get('protocol', ''),
                server_geo=data.get('server_geo', 'OTHER'),
                is_alive=data.get('is_alive', True),
                decay_rate=data.get('decay_rate', 0.05),
            )
            self._states[config_hash] = state
            imported += 1
        return imported
