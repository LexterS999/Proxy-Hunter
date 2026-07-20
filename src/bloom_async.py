"""
Асинхронный Bloom‑фильтр с шардированием и LRU-кешем для шардов.
Загружает в память только один шард за раз, выгружая старые при необходимости.
Использует детерминированный хеш (xxhash) для устойчивости между запусками.
"""

import logging
import os
import pickle
import asyncio
from pathlib import Path
from collections import OrderedDict
from typing import List, Dict
from pybloom_live import ScalableBloomFilter
import xxhash

logger = logging.getLogger(__name__)

BLOOM_VERSION = 2  # Версия фильтра


class ShardedBloomDeduplicator:
    def __init__(self, num_shards: int = 16, capacity: int = 100000, error_rate: float = 0.001,
                 cache_dir: str = "bloom_shards", max_shards_in_memory: int = 4):
        self.num_shards = num_shards
        self.capacity = capacity
        self.error_rate = error_rate
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_shards_in_memory = max_shards_in_memory
        self.shards = {}
        # Используем OrderedDict для LRU
        self._access_order = OrderedDict()
        self._locks = {i: asyncio.Semaphore(1) for i in range(num_shards)}

    def _get_shard_index(self, config: str) -> int:
        h = int(xxhash.xxh64(config.encode()).hexdigest(), 16)
        return h % self.num_shards

    def _get_shard_file(self, shard_idx: int) -> Path:
        return self.cache_dir / f"bloom_shard_{shard_idx}_v{BLOOM_VERSION}.bin"

    async def _load_shard(self, shard_idx: int):
        async with self._locks[shard_idx]:
            if shard_idx in self.shards:
                # Обновляем порядок доступа
                self._access_order.move_to_end(shard_idx)
                return

            if len(self.shards) >= self.max_shards_in_memory:
                # Выгружаем самый старый
                oldest = next(iter(self._access_order))
                del self._access_order[oldest]
                await self._save_shard(oldest)
                del self.shards[oldest]
                logger.debug(f"Evicted bloom shard {oldest} from memory")

            shard_file = self._get_shard_file(shard_idx)
            if shard_file.exists():
                try:
                    def load_pickle():
                        with open(shard_file, 'rb') as f:
                            return pickle.load(f)
                    data = await asyncio.to_thread(load_pickle)
                    self.shards[shard_idx] = data
                    self._access_order[shard_idx] = None
                    logger.info(f"Loaded bloom shard {shard_idx} from {shard_file}")
                except Exception as e:
                    logger.warning(f"Failed to load shard {shard_idx}: {e}. Creating new.")
                    self.shards[shard_idx] = ScalableBloomFilter(
                        initial_capacity=self.capacity,
                        error_rate=self.error_rate
                    )
                    self._access_order[shard_idx] = None
            else:
                self.shards[shard_idx] = ScalableBloomFilter(
                    initial_capacity=self.capacity,
                    error_rate=self.error_rate
                )
                self._access_order[shard_idx] = None

    async def _save_shard(self, shard_idx: int):
        if shard_idx not in self.shards:
            return
        shard_file = self._get_shard_file(shard_idx)
        try:
            def save_pickle():
                with open(shard_file, 'wb') as f:
                    pickle.dump(self.shards[shard_idx], f)
            await asyncio.to_thread(save_pickle)
            logger.debug(f"Saved bloom shard {shard_idx} to {shard_file}")
        except Exception as e:
            logger.error(f"Failed to save shard {shard_idx}: {e}")

    async def contains(self, config: str) -> bool:
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        return config in self.shards[shard_idx]

    async def contains_batch(self, configs: List[str]) -> Dict[str, bool]:
        """Пакетная проверка наличия в фильтре."""
        result = {}
        shard_map = {}
        for cfg in configs:
            shard_idx = self._get_shard_index(cfg)
            shard_map.setdefault(shard_idx, []).append(cfg)

        for shard_idx, cfgs in shard_map.items():
            await self._load_shard(shard_idx)
            bloom = self.shards.get(shard_idx)
            if bloom:
                for cfg in cfgs:
                    result[cfg] = cfg in bloom
            else:
                for cfg in cfgs:
                    result[cfg] = False
        return result

    async def add(self, config: str):
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        self.shards[shard_idx].add(config)
        self._access_order.move_to_end(shard_idx)

    async def save(self):
        for idx in list(self.shards.keys()):
            await self._save_shard(idx)

    async def reset(self):
        for shard_idx in range(self.num_shards):
            async with self._locks[shard_idx]:
                if shard_idx in self.shards:
                    del self.shards[shard_idx]
                if shard_idx in self._access_order:
                    del self._access_order[shard_idx]
                shard_file = self._get_shard_file(shard_idx)
                if shard_file.exists():
                    shard_file.unlink()
        logger.info("Reset all bloom shards")


AsyncBloomDeduplicator = ShardedBloomDeduplicator
