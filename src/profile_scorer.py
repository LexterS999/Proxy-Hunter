"""
profile_scorer.py - Скоринг профилей на основе истории
"""

import logging
import time
from typing import Dict, Any, List, Tuple

from db import HistoryDB, get_db

logger = logging.getLogger(__name__)


class ProfileScorer:
    """Скоринг конфигов на основе исторических профилей"""

    # Веса факторов
    W_SUCCESS_RATE = 0.5
    W_LATENCY = 0.3
    W_FRESHNESS = 0.2

    def __init__(self, db: HistoryDB = None, batch_size: int = 500):
        # [CHANGE] используем ленивую фабрику вместо HistoryDB() по умолчанию
        self.db = db or get_db()
        # [CHANGE] кеш профилей и очередь отложенной записи (батчинг)
        self._profile_cache: Dict[str, Dict] = {}
        self._dirty: Dict[str, Dict] = {}
        self._batch_size = batch_size

    # ------------------------------------------------------------------ #
    #  [CHANGE] Управление кешем и батчингом
    # ------------------------------------------------------------------ #

    def preload_profiles(self, fingerprints: List[str]):
        """Предзагрузка профилей пачкой перед скорингом."""
        if not fingerprints:
            return
        try:
            loaded = self.db.get_profiles_batch(fingerprints)
            self._profile_cache.update(loaded)
        except Exception as e:
            logger.debug(f"⚠️ preload_profiles: {e}")

    def flush(self):
        """Сбрасывает накопленные изменения профилей в БД одной транзакцией."""
        if not self._dirty:
            return
        try:
            self.db.update_profiles_batch(list(self._dirty.items()))
            self._dirty.clear()
        except Exception as e:
            logger.debug(f"⚠️ flush: {e}")

    def _get_profile_cached(self, fingerprint: str) -> Dict:
        if fingerprint not in self._profile_cache:
            try:
                self._profile_cache[fingerprint] = self.db.get_profile(fingerprint)
            except Exception:
                self._profile_cache[fingerprint] = {}
        return self._profile_cache[fingerprint]

    def _queue_update(self, fingerprint: str, profile: Dict):
        self._profile_cache[fingerprint] = profile
        self._dirty[fingerprint] = profile
        if len(self._dirty) >= self._batch_size:
            self.flush()

    # ------------------------------------------------------------------ #
    #  Скоринг
    # ------------------------------------------------------------------ #

    def score_profile(self, parsed_config: Dict[str, Any]) -> float:
        """
        Вычисляет скоринг конфига на основе истории профиля.
        [CHANGE] использует кеш + отложенную пакетную запись.
        """
        fingerprint = parsed_config.get('fingerprint', '')
        if not fingerprint:
            return 0.5

        profile = self._get_profile_cached(fingerprint)

        success_count = profile.get('success_count', 0)
        fail_count = profile.get('fail_count', 0)
        total = success_count + fail_count
        avg_latency = profile.get('avg_latency', 0.0)
        last_seen = profile.get('last_seen', 0)

        # 1. Success rate
        success_rate = (success_count / total) if total else 0.5

        # 2. Latency score (чем ниже, тем лучше; нормируем на 5000 мс)
        if avg_latency > 0:
            latency_score = max(0.0, 1.0 - avg_latency / 5000.0)
        else:
            latency_score = 0.5

        # 3. Freshness (свежесть)
        if last_seen:
            age_days = (time.time() - last_seen) / 86400.0
            freshness_score = max(0.0, 1.0 - age_days / 30.0)
        else:
            freshness_score = 0.5

        score = (
            self.W_SUCCESS_RATE * success_rate +
            self.W_LATENCY * latency_score +
            self.W_FRESHNESS * freshness_score
        )

        # Обновляем профиль (отложенно, пачкой)
        profile['last_seen'] = time.time()
        profile['avg_latency'] = avg_latency
        self._queue_update(fingerprint, profile)

        return round(max(0.0, min(1.0, score)), 4)

    def update_profile_history(self, fingerprint: str, success: bool, latency: float = 0.0):
        """Обновляет историю профиля после проверки."""
        profile = self._get_profile_cached(fingerprint)

        if success:
            profile['success_count'] = profile.get('success_count', 0) + 1
        else:
            profile['fail_count'] = profile.get('fail_count', 0) + 1

        # Скользящее среднее latency
        if latency > 0:
            old_avg = profile.get('avg_latency', 0.0)
            n = profile.get('latency_samples', 0)
            profile['avg_latency'] = (old_avg * n + latency) / (n + 1)
            profile['latency_samples'] = n + 1

        profile['last_seen'] = time.time()
        self._queue_update(fingerprint, profile)

    def get_adaptive_thresholds(self) -> Dict[str, float]:
        """
        Возвращает адаптивные пороги на основе накопленной статистики.
        [CHANGE] реально используется в pipeline для фильтрации по скору.
        """
        try:
            if not self._profile_cache:
                return {'min_score': 0.3}
            scores = []
            for fp, profile in self._profile_cache.items():
                total = profile.get('success_count', 0) + profile.get('fail_count', 0)
                if total:
                    scores.append(profile.get('success_count', 0) / total)
            if not scores:
                return {'min_score': 0.3}
            scores.sort()
            # Берём 25-й перцентиль как минимальный порог
            idx = max(0, len(scores) // 4 - 1)
            min_score = round(max(0.1, min(0.9, scores[idx])), 3)
            return {'min_score': min_score}
        except Exception:
            return {'min_score': 0.3}
