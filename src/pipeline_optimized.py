"""
pipeline_optimized.py - Оптимизированный пайплайн обработки прокси

Логирование настраивается ТОЛЬКО здесь (точка входа).
"""

import os
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
from profile_scorer import ProfileScorer
from active_checker import ActiveChecker
from deep_deduplicate import DeepDeduplicator
from xray_balancer import XrayBalancer
from db import get_db


# --------------------------------------------------------------------------- #
#  Worker верхнего уровня для параллельного парсинга (picklable)
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
        self.db = get_db()
        self.run_id = str(uuid.uuid4())[:8]

    async def run(self):
        """Запускает полный цикл обработки"""
        logger.info(f"🚀 Запуск пайплайна (run_id={self.run_id})")
        start = datetime.now()

        # Счётчики для сводки
        total_raw = total_valid = total_final = 0
        scored: List[Dict] = []
        checked: List[Dict] = []

        try:
            # Шаг 1: Сбор
            raw_configs = await self._fetch_configs()
            total_raw = len(raw_configs)
            logger.info(f"📥 Собрано конфигов: {total_raw}")

            if not raw_configs:
                logger.warning("⚠️ Нет конфигов для обработки")
                return

            # Шаг 2: Парсинг (параллельно)
            parsed = self._parse_configs_parallel(raw_configs)
            logger.info(f"🔍 Распознано конфигов: {len(parsed)}")

            # Шаг 3: Скоринг (кеш + батчинг)
            scored = self._score_configs(parsed)
            logger.info(f"📊 Оценено конфигов: {len(scored)}")

            # Шаг 4: Фильтрация по адаптивному порогу
            filtered = self._filter_by_score(scored)
            logger.info(f"🎯 После фильтрации: {len(filtered)}")

            # Шаг 5: Активная проверка
            checked = await self._active_check(filtered)
            total_valid = len(checked)
            logger.info(f"✅ Валидных после проверки: {total_valid}")

            # Шаг 6: Дедупликация
            unique = await self._deduplicate(checked)
            total_final = len(unique)
            logger.info(f"🧹 Уникальных конфигов: {total_final}")

            # Шаг 7: Архивация и генерация Xray
            self._save_results(unique)

            # [CHANGE] Шаг 8: запись сводки запуска в таблицу runs
            self._save_run_summary(total_raw, total_valid, total_final, scored, checked)

            # Сбрасываем накопленные обновления профилей одной транзакцией
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
        if not parsed:
            return []
        fingerprints = [p.get('fingerprint', '') for p in parsed if p.get('fingerprint')]
        self.scorer.preload_profiles(fingerprints)

        scored = []
        for item in tqdm(parsed, desc="Скоринг"):
            item['score'] = self.scorer.score_profile(item)
            scored.append(item)
        return scored

    # ------------------------------------------------------------------ #
    #  Шаг 4: Фильтрация по адаптивному порогу
    # ------------------------------------------------------------------ #

    def _filter_by_score(self, scored: List[Dict]) -> List[Dict]:
        if not scored:
            return []
        thresholds = self.scorer.get_adaptive_thresholds()
        min_score = thresholds.get('min_score', 0.3)
        logger.info(f"🎚️ Адаптивный порог скоринга: {min_score}")

        filtered = [item for item in scored if item.get('score', 0) >= min_score]
        if not filtered and scored:
            scored_sorted = sorted(scored, key=lambda x: x.get('score', 0), reverse=True)
            filtered = scored_sorted[:max(1, len(scored_sorted) // 2)]
            logger.warning("⚠️ Порог слишком строг — взята верхняя половина по скору")
        return filtered

    # ------------------------------------------------------------------ #
    #  Шаг 5: Активная проверка
    # ------------------------------------------------------------------ #

    async def _active_check(self, configs: List[Dict]) -> List[Dict]:
        if not configs:
            return []
        checker = ActiveChecker()
        try:
            raw_configs = [c.get('raw', '') for c in configs]
            results = await checker.check_batch(raw_configs)

            valid = []
            for item, result in zip(configs, results):
                fp = item.get('fingerprint', '')
                if isinstance(result, dict) and result.get('valid'):
                    item['latency'] = result.get('tcp_latency', -1)
                    if fp:
                        self.scorer.update_profile_history(fp, success=True, latency=item['latency'])
                    valid.append(item)
                else:
                    if fp:
                        self.scorer.update_profile_history(fp, success=False)
            return valid
        finally:
            await checker.close()

    # ------------------------------------------------------------------ #
    #  Шаг 6: Дедупликация
    # ------------------------------------------------------------------ #

    async def _deduplicate(self, configs: List[Dict]) -> List[Dict]:
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
        try:
            os.makedirs('configs', exist_ok=True)
            raw_configs = [c.get('raw', '') for c in configs if c.get('raw')]

            with open(self.config.ARCHIVE_FILE, 'w', encoding='utf-8') as f:
                for i, cfg in enumerate(raw_configs, 1):
                    f.write(f"# Config {i}\n{cfg}\n")

            with open(self.config.SIMPLE_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(raw_configs))

            logger.info(f"💾 Сохранено: {self.config.ARCHIVE_FILE}, {self.config.SIMPLE_FILE}")
            self.balancer.generate_config(configs)
        except Exception as e:
            logger.error(f"❌ Ошибка сохранения: {e}")

    # ------------------------------------------------------------------ #
    #  [CHANGE] Шаг 8: Сводка запуска (таблица runs)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _percentile(data: List[float], p: float) -> float:
        """Вычисляет перцентиль без numpy (линейная интерполяция)."""
        if not data:
            return 0.0
        data = sorted(data)
        k = (len(data) - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, len(data) - 1)
        if f == c:
            return float(data[f])
        return float(data[f] + (data[c] - data[f]) * (k - f))

    def _save_run_summary(self, total_raw: int, total_valid: int, total_final: int,
                          scored: List[Dict], checked: List[Dict]):
        """Записывает агрегированную сводку запуска в таблицу runs."""
        try:
            latencies = [c.get('latency', 0) for c in checked if c.get('latency', 0) > 0]
            avg_score = (sum(c.get('score', 0) for c in scored) / len(scored)) if scored else 0.0
            success_rate = (total_final / total_valid * 100) if total_valid else 0.0

            protocols: Dict[str, int] = {}
            for c in checked:
                proto = c.get('protocol', 'unknown')
                protocols[proto] = protocols.get(proto, 0) + 1

            self.db.add_run_summary(
                run_id=self.run_id,
                total_raw=total_raw,
                total_valid=total_valid,
                total_final=total_final,
                avg_score=round(avg_score, 4),
                p50_latency=self._percentile(latencies, 50),
                p95_latency=self._percentile(latencies, 95),
                p99_latency=self._percentile(latencies, 99),
                success_rate=round(success_rate, 2),
                protocols=protocols,
            )
            logger.info("📊 Сводка запуска сохранена в БД")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось сохранить сводку запуска: {e}")


async def main():
    pipeline = OptimizedPipeline()
    await pipeline.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⏹️ Остановлено пользователем")
