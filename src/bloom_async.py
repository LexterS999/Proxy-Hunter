"""
Асинхронная обёртка над синхронным Bloom‑фильтром из pybloom_live.
Использует шардирование для снижения нагрузки на память и ускорения загрузки.
"""

import logging
import os
import pickle
from pathlib import Path
from pybloom_live import ScalableBloomFilter

logger = logging.getLogger(__name__)

class ShardedBloomDeduplicator:
    """
    Асинхронный дедупликатор на основе масштабируемых Bloom‑фильтров с шардированием.
    Каждый шард сохраняется в отдельный файл, что позволяет загружать только нужный.
    """

    def __init__(self, num_shards: int = 16, capacity: int = 100000, error_rate: float = 0.001, cache_dir: str = "bloom_shards"):
        self.num_shards = num_shards
        self.capacity = capacity
        self.error_rate = error_rate
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.shards = [None] * num_shards  # Ленивая загрузка
        self._loaded_shards = set()

    def _get_shard_index(self, config: str) -> int:
        """Определяет номер шарда по хешу конфигурации."""
        return abs(hash(config)) % self.num_shards

    def _get_shard_file(self, shard_idx: int) -> Path:
        return self.cache_dir / f"bloom_shard_{shard_idx}.bin"

    async def _ensure_shard_loaded(self, shard_idx: int):
        """Загружает шард из файла, если он ещё не загружен."""
        if shard_idx in self._loaded_shards and self.shards[shard_idx] is not None:
            return
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
        self._loaded_shards.add(shard_idx)

    async def contains(self, config: str) -> bool:
        """Проверяет, содержится ли конфигурация в соответствующем шарде."""
        shard_idx = self._get_shard_index(config)
        await self._ensure_shard_loaded(shard_idx)
        return config in self.shards[shard_idx]

    async def add(self, config: str):
        """Добавляет конфигурацию в соответствующий шард."""
        shard_idx = self._get_shard_index(config)
        await self._ensure_shard_loaded(shard_idx)
        self.shards[shard_idx].add(config)

    async def save(self):
        """Сохраняет все загруженные шарды в файлы."""
        for shard_idx in self._loaded_shards:
            if self.shards[shard_idx] is not None:
                shard_file = self._get_shard_file(shard_idx)
                try:
                    with open(shard_file, 'wb') as f:
                        pickle.dump(self.shards[shard_idx], f)
                    logger.debug(f"Saved bloom shard {shard_idx} to {shard_file}")
                except Exception as e:
                    logger.error(f"Failed to save shard {shard_idx}: {e}")

    async def reset(self):
        """Очищает все шарды и удаляет файлы кеша."""
        for shard_idx in range(self.num_shards):
            self.shards[shard_idx] = None
            shard_file = self._get_shard_file(shard_idx)
            if shard_file.exists():
                shard_file.unlink()
        self._loaded_shards.clear()
        logger.info("Reset all bloom shards")
