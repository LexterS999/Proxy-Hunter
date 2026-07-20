"""
bloom_async.py - Асинхронный шардированный Bloom-фильтр для дедупликации
"""

import asyncio
import hashlib
import os
import pickle
from typing import Set

try:
    import xxhash
    _HAS_XXHASH = True
except ImportError:
    _HAS_XXHASH = False


class BloomFilter:
    """Простой Bloom-фильтр"""

    def __init__(self, capacity: int = 1000000, error_rate: float = 0.001):
        self.capacity = capacity
        self.error_rate = error_rate
        self.bit_array = bytearray(capacity // 8 + 1)
        self.num_hashes = 3
        self.count = 0

    def _get_bit_indices(self, item: str) -> list:
        """Получает индексы битов для элемента (детерминированно)."""
        indices = []
        for i in range(self.num_hashes):
            if _HAS_XXHASH:
                h = xxhash.xxh64(f"{item}:{i}".encode('utf-8', errors='ignore')).hexdigest()
            else:
                h = hashlib.sha256(f"{item}:{i}".encode('utf-8', errors='ignore')).hexdigest()
            indices.append(int(h, 16) % len(self.bit_array))
        return indices

    def add(self, item: str):
        """Добавляет элемент"""
        for idx in self._get_bit_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self.count += 1

    def contains(self, item: str) -> bool:
        """Проверяет наличие элемента"""
        for idx in self._get_bit_indices(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True


class AsyncBloomFilter:
    """Асинхронный шардированный Bloom-фильтр"""

    def __init__(self, shard_dir: str = 'configs/bloom_shards', num_shards: int = 10,
                 capacity: int = 1000000, error_rate: float = 0.001,
                 max_shards_in_memory: int = 3):
        self.shard_dir = shard_dir
        self.num_shards = num_shards
        self.capacity = capacity
        self.error_rate = error_rate
        self.max_shards_in_memory = max_shards_in_memory

        os.makedirs(shard_dir, exist_ok=True)

        self._shards = {}
        self._shard_access = {}
        self._lock = asyncio.Lock()

    def _get_shard_index(self, config: str) -> int:
        """
        [CHANGE] Детерминированный хеш шарда.
        Ранее использовался встроенный hash(), который рандомизирован между
        запусками (PYTHONHASHSEED) → шарды, сохранённые на диск, становились
        несовместимы между запусками CI. Теперь xxhash (или sha256 fallback).
        """
        data = config.encode('utf-8', errors='ignore')
        if _HAS_XXHASH:
            h = int(xxhash.xxh64(data).hexdigest(), 16)
        else:
            h = int(hashlib.sha256(data).hexdigest(), 16)
        return h % self.num_shards

    async def _load_shard(self, shard_id: int) -> BloomFilter:
        """Загружает шард (блокирующий I/O вынесен в поток)."""
        if shard_id in self._shards:
            self._shard_access[shard_id] = self._shard_access.get(shard_id, 0) + 1
            return self._shards[shard_id]

        # Eviction LRU
        if len(self._shards) >= self.max_shards_in_memory:
            lru_shard = min(self._shards.keys(), key=lambda k: self._shard_access.get(k, 0))
            await self._save_shard(lru_shard)
            del self._shards[lru_shard]

        # [CHANGE] загрузка в отдельном потоке, чтобы не блокировать event loop
        bloom = await asyncio.to_thread(self._load_shard_sync, shard_id)
        self._shards[shard_id] = bloom
        self._shard_access[shard_id] = self._shard_access.get(shard_id, 0) + 1
        return bloom

    def _load_shard_sync(self, shard_id: int) -> BloomFilter:
        """Синхронная загрузка шарда с диска (вызывается в потоке)."""
        path = os.path.join(self.shard_dir, f"shard_{shard_id}.pkl")
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Ошибка загрузки шарда {shard_id}: {e}")
        return BloomFilter(capacity=self.capacity // self.num_shards,
                           error_rate=self.error_rate)

    async def _save_shard(self, shard_id: int):
        """Сохраняет шард (блокирующий I/O вынесен в поток)."""
        if shard_id in self._shards:
            await asyncio.to_thread(self._save_shard_sync, shard_id)

    def _save_shard_sync(self, shard_id: int):
        """Синхронное сохранение шарда на диск (вызывается в потоке)."""
        path = os.path.join(self.shard_dir, f"shard_{shard_id}.pkl")
        try:
            with open(path, 'wb') as f:
                pickle.dump(self._shards[shard_id], f)
        except Exception as e:
            print(f"Ошибка сохранения шарда {shard_id}: {e}")

    async def contains(self, config: str) -> bool:
        """Проверяет наличие конфига"""
        async with self._lock:
            shard_id = self._get_shard_index(config)
            bloom = await self._load_shard(shard_id)
            return bloom.contains(config)

    async def add(self, config: str):
        """Добавляет конфиг"""
        async with self._lock:
            shard_id = self._get_shard_index(config)
            bloom = await self._load_shard(shard_id)
            bloom.add(config)

    async def save_all(self):
        """Сохраняет все шарды в памяти"""
        async with self._lock:
            for shard_id in list(self._shards.keys()):
                await self._save_shard(shard_id)
