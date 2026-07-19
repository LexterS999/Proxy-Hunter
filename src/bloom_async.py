"""
Асинхронный Bloom‑фильтр с шардированием и LRU-кешем для шардов.
Загружает в память только один шард за раз, выгружая старые при необходимости.
"""

import logging
import os
import pickle
from pathlib import Path
from functools import lru_cache
from pybloom_live import ScalableBloomFilter
import asyncio

logger = logging.getLogger(__name__)


class ShardedBloomDeduplicator:
    """
    Дедупликатор на основе масштабируемых Bloom‑фильтров с шардированием и LRU-выгрузкой.
    """

    def __init__(self, num_shards: int = 16, capacity: int = 100000, error_rate: float = 0.001,
                 cache_dir: str = "bloom_shards", max_shards_in_memory: int = 4):
        self.num_shards = num_shards
        self.capacity = capacity
        self.error_rate = error_rate
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_shards_in_memory = max_shards_in_memory
        self.shards = {}  # shard_idx -> BloomFilter
        self._lock = asyncio.Lock()
        self._access_order = []  # список для LRU

    def _get_shard_index(self, config: str) -> int:
        return abs(hash(config)) % self.num_shards

    def _get_shard_file(self, shard_idx: int) -> Path:
        return self.cache_dir / f"bloom_shard_{shard_idx}.bin"

    async def _load_shard(self, shard_idx: int):
        """Загружает шард из файла или создаёт новый."""
        async with self._lock:
            if shard_idx in self.shards:
                # Обновляем порядок доступа
                if shard_idx in self._access_order:
                    self._access_order.remove(shard_idx)
                self._access_order.append(shard_idx)
                return

            # Проверяем, не превышен ли лимит
            if len(self.shards) >= self.max_shards_in_memory:
                # Выгружаем самый старый шард
                oldest = self._access_order.pop(0)
                # Сохраняем перед выгрузкой
                await self._save_shard(oldest)
                del self.shards[oldest]
                logger.debug(f"Evicted bloom shard {oldest} from memory")

            shard_file = self._get_shard_file(shard_idx)
            if shard_file.exists():
                try:
                    with open(shard_file, 'rb') as f:
                        data = pickle.load(f)
                    self.shards[shard_idx] = data
                    logger.info(f"Loaded bloom shard {shard_idx} from {shard_file}")
                except Exception as e:
                    logger.warning(f"Failed to load shard {shard_idx}: {e}. Creating new.")
                    self.shards[shard_idx] = ScalableBloomFilter(
                        initial_capacity=self.capacity,
                        error_rate=self.error_rate
                    )
            else:
                self.shards[shard_idx] = ScalableBloomFilter(
                    initial_capacity=self.capacity,
                    error_rate=self.error_rate
                )
            self._access_order.append(shard_idx)

    async def _save_shard(self, shard_idx: int):
        """Сохраняет шард на диск."""
        if shard_idx not in self.shards:
            return
        shard_file = self._get_shard_file(shard_idx)
        try:
            with open(shard_file, 'wb') as f:
                pickle.dump(self.shards[shard_idx], f)
            logger.debug(f"Saved bloom shard {shard_idx} to {shard_file}")
        except Exception as e:
            logger.error(f"Failed to save shard {shard_idx}: {e}")

    async def contains(self, config: str) -> bool:
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        return config in self.shards[shard_idx]

    async def add(self, config: str):
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        self.shards[shard_idx].add(config)

    async def save(self):
        """Сохраняет все загруженные шарды."""
        async with self._lock:
            for idx in list(self.shards.keys()):
                await self._save_shard(idx)

    async def reset(self):
        """Очищает все шарды и удаляет файлы кеша."""
        async with self._lock:
            for shard_idx in range(self.num_shards):
                if shard_idx in self.shards:
                    del self.shards[shard_idx]
                shard_file = self._get_shard_file(shard_idx)
                if shard_file.exists():
                    shard_file.unlink()
            self._access_order.clear()
            logger.info("Reset all bloom shards")


# Для обратной совместимости
AsyncBloomDeduplicator = ShardedBloomDeduplicator
