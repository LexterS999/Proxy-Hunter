"""
pipeline_optimized.py - Оптимизированный пайплайн обработки прокси

[CHANGE] логирование настраивается ТОЛЬКО здесь (точка входа).
Из config.py и xray_balancer.py logging.basicConfig удалён.
"""

import os
import sys
import asyncio
import logging
import uuid
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from typing import List, Dict, Optional

from tqdm import tqdm

# Точка входа — настраиваем логирование один раз
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from config import Config
from config_parser import ConfigParser
from config_validator import ConfigValidator
from parse_fallback import FallbackParser
from config_identity import ConfigIdentity
from profile_scorer import ProfileScorer
from active_checker import ActiveChecker
from deep_deduplicate import DeepDeduplicator
from xray_balancer import XrayBalancer
from db import get_db

# [CHANGE] удалён мёртвый импорт:
#   from quality_analyzer_enhanced import EnhancedQualityAnalyzer
# Модуль quality_analyzer_enhanced.py (JSON-хранилище) удалён —
# единственным источником истории теперь является SQLite (db.py).


# --------------------------------------------------------------------------- #
#  [CHANGE] Worker верхнего уровня для параллельного парсинга (picklable)
# --------------------------------------------------------------------------- #

def _parse_worker(configs_chunk: List[str]) -> List[Optional[Dict]]:
    """Парсит чанк конфигов в отдельном процессе."""
    parser = ConfigParser()
    fallback = FallbackParser()
    results = []
    for cfg in configs_chunk:
        parsed = parser.parse_config(cfg)
        if not parsed:
            parsed = fallback.parse_broken_config(cfg)
        results.append(parsed)
    return results


class OptimizedPipeline:
    """Оптимизированный пайплайн обработки прокси"""

    def __init__(self):
        self.config = Config()
        self.validator = ConfigValidator()
        self.scorer = ProfileScorer()
        self.deduplicator = DeepDeduplicator()
        self.balancer = XrayBalancer()
        # [CHANGE] ленивая инициализация БД через фабрику
        self.db = get_db()
        self.run_id = str(uuid.uuid4())[:8]

    async def run(self):
        """Запускает полный цикл обработки"""
        logger.info(f"🚀 Запуск пайплайна (run_id={self.run_id})")
        start = datetime.now()

        try:
            # Шаг 1: Сбор конфигов из каналов
            raw_configs = await self._fetch_configs()
            logger.info(f"📥 Собрано конфигов: {len(raw_configs)}")

            if not raw_configs:
                logger.warning("⚠️ Нет конфигов для обработки")
                return

            # Шаг 2: Парсинг (параллельно)
            parsed = self._parse_configs_parallel(raw_configs)
            logger.info(f"🔍 Распознано конфигов: {len(parsed)}")

            # Шаг 3: Скоринг (с кешем и батчингом)
            scored = self._score_configs(parsed)
            logger.info(f"📊 Оценено конфигов: {len(scored)}")

            # Шаг 4: Фильтрация по адаптивному порогу
            filtered = self._filter_by_score(scored)
            logger.info(f"🎯 После фильтрации: {len(filtered)}")

            # Шаг 5: Активная проверка
            checked = await self._active_check(filtered)
            logger.info(f"✅ Валидных после проверки: {len(checked)}")

            # Шаг 6: Дедупликация
            unique = await self._deduplicate(checked)
            logger.info(f"🧹 Уникальных конфигов: {len(unique)}")

            # Шаг 7: Архивация и генерация Xray
            self._save_results(unique)

            # [CHANGE] сбрасываем накопленные обновления профилей в БД одной транзакцией
            self.scorer.flush()

            elapsed = (datetime.now() - start).total_seconds()
            logger.info(f"🏁 Пайплайн завершён за {elapsed:.1f} сек")

        except Exception as e:
            logger.error(f"❌ Ошибка пайплайна: {e}", exc_info=True)
            self.scorer.flush()
            raise

    # ------------------------------------------------------------------ #
    #  Шаг 1: Сбор
    # ------------------------------------------------------------------ #

    async def _fetch_configs(self) -> List[str]:
        """Собирает конфиги из активных каналов."""
        try:
            from fetch_configs import AsyncConfigFetcher
            channels = self.config.get_enabled_channels()
            fetcher = AsyncConfigFetcher()
            try:
                all_configs = []
                for url in channels:
                    try:
                        configs = await fetcher.fetch_channel(url)
                        all_configs.extend(configs)
                    except Exception as e:
                        logger.debug(f"⚠️ Канал {url}: {e}")
                return all_configs
            finally:
                await fetcher.close()
        except Exception as e:
            logger.error(f"❌ Ошибка сбора: {e}")
            return []

    # ------------------------------------------------------------------ #
    #  Шаг 2: Парсинг (параллельный)
    # ------------------------------------------------------------------ #

    def _parse_configs_parallel(self, configs: List[str]) -> List[Dict]:
        """
        [CHANGE] Параллельный парсинг через ProcessPoolExecutor (CPU-bound).
        При недоступности multiprocessing — синхронный fallback.
        """
        if not configs:
            return []

        cpu = max(1, (multiprocessing.cpu_count() or 2) - 1)
        chunk_size = max(100, len(configs) // (cpu * 4))
        chunks = [configs[i:i + chunk_size] for i in range(0, len(configs), chunk_size)]

        results: List[Optional[Dict]] = []
        try:
            with ProcessPoolExecutor(max_workers=cpu) as executor:
                for chunk_result in tqdm(
                    executor.map(_parse_worker, chunks),
                    total=len(chunks), desc="Парсинг"
                ):
                    results.extend(chunk_result)
        except Exception as e:
            logger.warning(f"⚠️ Параллельный парсинг недоступен ({e}) — синхронный режим")
            results = []
            for chunk in tqdm(chunks, desc="Парсинг"):
                results.extend(_parse_worker(chunk))

        return [r for r in results if r]

    # ------------------------------------------------------------------ #
    #  Шаг 3: Скоринг
    # ------------------------------------------------------------------ #

    def _score_configs(self, parsed: List[Dict]) -> List[Dict]:
        """
        [CHANGE] Скоринг с предзагрузкой профилей пачкой и отложенной записью.
        Устраняет N+1 запросов к SQLite.
        """
        if not parsed:
            return []

        # Предзагружаем профили одной пачкой
        fingerprints = [p.get('fingerprint', '') for p in parsed if p.get('fingerprint')]
        self.scorer.preload_profiles(fingerprints)

        scored = []
        for item in tqdm(parsed, desc="Скоринг"):
            score = self.scorer.score_profile(item)
            item['score'] = score
            scored.append(item)
        return scored

    # ------------------------------------------------------------------ #
    #  Шаг 4: Фильтрация по адаптивному порогу
    # ------------------------------------------------------------------ #

    def _filter_by_score(self, scored: List[Dict]) -> List[Dict]:
        """
        [CHANGE] Реальный адаптивный порог из get_adaptive_thresholds().
        Ранее min_score был захардкожен в 0.0 (фильтр ничего не фильтровал).
        """
        if not scored:
            return []

        thresholds = self.scorer.get_adaptive_thresholds()
        min_score = thresholds.get('min_score', 0.3)
        logger.info(f"🎚️ Адаптивный порог скоринга: {min_score}")

        filtered = [item for item in scored if item.get('score', 0) >= min_score]

        # Fallback: если всё отфильтровалось — берём верхнюю половину по скору
        if not filtered and scored:
            scored_sorted = sorted(scored, key=lambda x: x.get('score', 0), reverse=True)
            filtered = scored_sorted[:max(1, len(scored_sorted) // 2)]
            logger.warning("⚠️ Порог слишком строг — взята верхняя половина по скору")

        return filtered

    # ------------------------------------------------------------------ #
    #  Шаг 5: Активная проверка
    # ------------------------------------------------------------------ #

    async def _active_check(self, configs: List[Dict]) -> List[Dict]:
        """Активная проверка (TCP/HTTP)."""
        if not configs:
            return []

        checker = ActiveChecker()
        try:
            raw_configs = [c.get('raw', '') for c in configs]
            results = await checker.check_batch(raw_configs)

            valid = []
            for item, result in zip(configs, results):
                if isinstance(result, dict) and result.get('valid'):
                    item['latency'] = result.get('tcp_latency', -1)
                    # Обновляем историю профиля
                    fp = item.get('fingerprint', '')
                    if fp:
                        self.scorer.update_profile_history(
                            fp, success=True, latency=item['latency']
                        )
                    valid.append(item)
                else:
                    fp = item.get('fingerprint', '')
                    if fp:
                        self.scorer.update_profile_history(fp, success=False)
            return valid
        finally:
            await checker.close()

    # ------------------------------------------------------------------ #
    #  Шаг 6: Дедупликация
    # ------------------------------------------------------------------ #

    async def _deduplicate(self, configs: List[Dict]) -> List[Dict]:
        """Глубокая дедупликация."""
        if not configs:
            return []
        raw_configs = [c.get('raw', '') for c in configs]
        unique_raw = await self.deduplicator.deduplicate_configs_async(raw_configs)
        unique_set = set(unique_raw)
        return [c for c in configs if c.get('raw', '') in unique_set]

    # ------------------------------------------------------------------ #
    #  Шаг 7: Сохранение результатов
    # ------------------------------------------------------------------ #

    def _save_results(self, configs: List[Dict]):
        """Сохраняет архив, простой список и Xray-конфиг."""
        try:
            os.makedirs('configs', exist_ok=True)
            raw_configs = [c.get('raw', '') for c in configs if c.get('raw')]

            # Архив с именами
            archive_path = self.config.ARCHIVE_FILE
            with open(archive_path, 'w', encoding='utf-8') as f:
                for i, cfg in enumerate(raw_configs, 1):
                    f.write(f"# Config {i}\n{cfg}\n")

            # Простой список
            simple_path = self.config.SIMPLE_FILE
            with open(simple_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(raw_configs))

            logger.info(f"💾 Сохранено: {archive_path}, {simple_path}")

            # Xray-конфиг с балансировкой
            self.balancer.generate_config(configs)

        except Exception as e:
            logger.error(f"❌ Ошибка сохранения: {e}")


async def main():
    pipeline = OptimizedPipeline()
    await pipeline.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⏹️ Остановлено пользователем")
