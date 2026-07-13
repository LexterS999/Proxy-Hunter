"""
Асинхронная обёртка над синхронным Bloom‑фильтром из pybloom_live.
Использует ScalableBloomFilter (автоматически масштабируется при заполнении).
"""

import logging
import os
import pickle
from pathlib import Path
from pybloom_live import ScalableBloomFilter

logger = logging.getLogger(__name__)


class AsyncBloomDeduplicator:
    """
    Асинхронный дедупликатор на основе масштабируемого Bloom‑фильтра.
    Сохраняет состояние в файл между запусками.
    """

    def __init__(self, capacity: int = 100000, error_rate: float = 0.001, cache_file: str = "bloom_cache.bin"):
        self.capacity = capacity
        self.error_rate = error_rate
        self.cache_file = cache_file
        self.bloom = None
        self._loaded = False

    async def _ensure_loaded(self):
        """Загружает фильтр из файла при первом использовании."""
        if self._loaded and self.bloom is not None:
            return
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'rb') as f:
                    data = pickle.load(f)
                self.bloom = data
                logger.info(f"Loaded bloom filter from {self.cache_file} (capacity={self.bloom.capacity})")
            except Exception as e:
                logger.warning(f"Failed to load bloom filter: {e}. Starting fresh.")
                self.bloom = ScalableBloomFilter(
                    initial_capacity=self.capacity,
                    error_rate=self.error_rate
                )
        else:
            logger.info("No existing bloom filter cache found. Starting fresh.")
            self.bloom = ScalableBloomFilter(
                initial_capacity=self.capacity,
                error_rate=self.error_rate
            )
        self._loaded = True

    async def contains(self, config: str) -> bool:
        """Проверяет, содержится ли конфигурация в фильтре."""
        await self._ensure_loaded()
        return config in self.bloom

    async def add(self, config: str):
        """Добавляет конфигурацию в фильтр."""
        await self._ensure_loaded()
        self.bloom.add(config)

    async def save(self):
        """Сохраняет текущее состояние фильтра в файл."""
        if self.bloom is None:
            return
        try:
            Path(self.cache_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.bloom, f)
            logger.info(f"Saved bloom filter to {self.cache_file}")
        except Exception as e:
            logger.error(f"Failed to save bloom filter: {e}")

    async def reset(self):
        """Очищает фильтр и удаляет файл кеша."""
        self.bloom = ScalableBloomFilter(
            initial_capacity=self.capacity,
            error_rate=self.error_rate
        )
        self._loaded = True
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
            logger.info(f"Removed bloom cache file {self.cache_file}")
