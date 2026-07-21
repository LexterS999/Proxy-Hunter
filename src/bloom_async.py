"""
Асинхронный Bloom‑фильтр с шардированием и LRU-кешем для шардов.
Загружает в память только один шард за раз, выгружая старые при необходимости.

ИСПРАВЛЕНО: asyncio.Lock() создаётся лениво внутри работающего event loop,
а не при импорте модуля (Python 3.10+ DeprecationWarning / 3.12+ breakage).
"""

import logging
import os
import pickle
import hashlib
import hmac
from pathlib import Path
from typing import Optional, Dict, List
from pybloom_live import ScalableBloomFilter
import asyncio

logger = logging.getLogger(__name__)

# Ключ для HMAC-верификации целостности шардов (защита от подмены pickle)
_SHARD_INTEGRITY_KEY = os.getenv('PROXY_HUNTER_BLOOM_KEY', 'bloom_shard_integrity_2026').encode()


class ShardedBloomDeduplicator:
    """
    Дедупликатор на основе масштабируемых Bloom‑фильтров с шардированием и LRU-выгрузкой.
    """

    def __init__(
        self,
        num_shards: int = 16,
        capacity: int = 100000,
        error_rate: float = 0.001,
        cache_dir: str = "bloom_shards",
        max_shards_in_memory: int = 4
    ) -> None:
        self.num_shards = num_shards
        self.capacity = capacity
        self.error_rate = error_rate
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_shards_in_memory = max_shards_in_memory
        self.shards: Dict[int, ScalableBloomFilter] = {}  # shard_idx -> BloomFilter
        self._lock: Optional[asyncio.Lock] = None  # ИСПРАВЛЕНО: ленивое создание
        self._access_order: List[int] = []  # список для LRU

    def _get_lock(self) -> asyncio.Lock:
        """ИСПРАВЛЕНО: Ленивое создание Lock внутри работающего event loop."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _get_shard_index(self, config: str) -> int:
        return abs(hash(config)) % self.num_shards

    def _get_shard_file(self, shard_idx: int) -> Path:
        return self.cache_dir / f"bloom_shard_{shard_idx}.bin"

    def _get_shard_sig_file(self, shard_idx: int) -> Path:
        """Файл подписи для верификации целостности шарда."""
        return self.cache_dir / f"bloom_shard_{shard_idx}.sig"

    def _compute_signature(self, data: bytes) -> str:
        """Вычисляет HMAC-подпись для верификации данных шарда."""
        return hmac.new(_SHARD_INTEGRITY_KEY, data, hashlib.sha256).hexdigest()

    def _verify_signature(self, data: bytes, shard_idx: int) -> bool:
        """Проверяет HMAC-подпись шарда перед десериализацией."""
        sig_file = self._get_shard_sig_file(shard_idx)
        if not sig_file.exists():
            # Если подписи нет (старый формат), принимаем данные
            return True
        try:
            stored_sig = sig_file.read_text().strip()
            computed_sig = self._compute_signature(data)
            return hmac.compare_digest(stored_sig, computed_sig)
        except Exception:
            return False

    def _save_signature(self, data: bytes, shard_idx: int) -> None:
        """Сохраняет HMAC-подпись шарда."""
        sig_file = self._get_shard_sig_file(shard_idx)
        try:
            sig_file.write_text(self._compute_signature(data))
        except Exception as e:
            logger.warning(f"Failed to save shard signature {shard_idx}: {e}")

    async def _load_shard(self, shard_idx: int) -> None:
        """Загружает шард из файла или создаёт новый."""
        lock = self._get_lock()
        async with lock:
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
                    raw_data = shard_file.read_bytes()
                    # ИСПРАВЛЕНО: Верификация целостности перед pickle.load
                    if not self._verify_signature(raw_data, shard_idx):
                        logger.warning(
                            f"Shard {shard_idx} signature verification FAILED. "
                            f"Creating new shard (possible tampering)."
                        )
                        self.shards[shard_idx] = ScalableBloomFilter(
                            initial_capacity=self.capacity,
                            error_rate=self.error_rate
                        )
                    else:
                        import io
                        data = pickle.load(io.BytesIO(raw_data))
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

    async def _save_shard(self, shard_idx: int) -> None:
        """Сохраняет шард на диск с HMAC-подписью."""
        if shard_idx not in self.shards:
            return
        shard_file = self._get_shard_file(shard_idx)
        try:
            import io
            buffer = io.BytesIO()
            pickle.dump(self.shards[shard_idx], buffer)
            raw_data = buffer.getvalue()
            shard_file.write_bytes(raw_data)
            # Сохраняем подпись для верификации
            self._save_signature(raw_data, shard_idx)
            logger.debug(f"Saved bloom shard {shard_idx} to {shard_file}")
        except Exception as e:
            logger.error(f"Failed to save shard {shard_idx}: {e}")

    async def contains(self, config: str) -> bool:
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        return config in self.shards[shard_idx]

    async def add(self, config: str) -> None:
        shard_idx = self._get_shard_index(config)
        await self._load_shard(shard_idx)
        self.shards[shard_idx].add(config)

    async def save(self) -> None:
        """Сохраняет все загруженные шарды."""
        lock = self._get_lock()
        async with lock:
            for idx in list(self.shards.keys()):
                await self._save_shard(idx)

    async def reset(self) -> None:
        """Очищает все шарды и удаляет файлы кеша."""
        lock = self._get_lock()
        async with lock:
            for shard_idx in range(self.num_shards):
                if shard_idx in self.shards:
                    del self.shards[shard_idx]
                shard_file = self._get_shard_file(shard_idx)
                if shard_file.exists():
                    shard_file.unlink()
                sig_file = self._get_shard_sig_file(shard_idx)
                if sig_file.exists():
                    sig_file.unlink()
            self._access_order.clear()
            logger.info("Reset all bloom shards")


# Для обратной совместимости
AsyncBloomDeduplicator = ShardedBloomDeduplicator
