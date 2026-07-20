"""
deep_deduplicate.py - Глубокая дедупликация с использованием xxHash и Bloom-фильтров
"""

import asyncio
import ipaddress
from typing import List, Set, Dict, Optional, Tuple

from config_identity import ConfigIdentity
from bloom_async import AsyncBloomFilter


class DeepDeduplicator:
    """Глубокая дедупликация конфигов"""

    def __init__(self):
        self.bloom = AsyncBloomFilter()
        self._index: Set[str] = set()

    async def deduplicate_configs_async(self, configs: List[str]) -> List[str]:
        """
        Асинхронная дедупликация с использованием Bloom-фильтра и индекса по подсетям.
        [CHANGE] O(n²) проверка схожести заменена на индекс по /24 (IPv4) и /48 (IPv6).
        """
        unique_configs = []
        seen_fingerprints: Set[str] = set()
        # [CHANGE] индекс: ключ подсети -> список host'ов в этой подсети
        subnet_index: Dict[str, List[str]] = {}

        for config in configs:
            # Быстрая проверка через Bloom-фильтр
            if await self.bloom.contains(config):
                # Возможный дубликат — проверяем точно по отпечатку
                fp = ConfigIdentity.get_fingerprint(config)
                if fp in seen_fingerprints:
                    continue

                # [CHANGE] проверка «похожих серверов» только в пределах одной подсети (O(1)-поиск)
                ep = ConfigIdentity.get_endpoint(config)
                subnet = self._get_subnet_key(ep.host)
                if subnet and subnet in subnet_index:
                    if any(self.is_similar_server(ep.host, seen_host)
                           for seen_host in subnet_index[subnet]):
                        continue

                # Не дубликат — добавляем
                seen_fingerprints.add(fp)
                if subnet:
                    subnet_index.setdefault(subnet, []).append(ep.host)
                unique_configs.append(config)
            else:
                # Новый конфиг
                await self.bloom.add(config)
                fp = ConfigIdentity.get_fingerprint(config)
                seen_fingerprints.add(fp)
                ep = ConfigIdentity.get_endpoint(config)
                subnet = self._get_subnet_key(ep.host)
                if subnet:
                    subnet_index.setdefault(subnet, []).append(ep.host)
                unique_configs.append(config)

        await self.bloom.save_all()
        return unique_configs

    @staticmethod
    def _get_subnet_key(host: str) -> Optional[str]:
        """
        [CHANGE] Возвращает ключ подсети для кластеризации:
        IPv4 -> /24 (первые 3 октета), IPv6 -> /48.
        Для доменов возвращает None (не кластеризуем по подсети).
        """
        if not host:
            return None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None  # доменное имя
        try:
            if ip.version == 4:
                net = ipaddress.ip_network(f"{host}/24", strict=False)
                return f"v4:{net.network_address}"
            else:
                net = ipaddress.ip_network(f"{host}/48", strict=False)
                return f"v6:{net.network_address}"
        except ValueError:
            return None

    def is_similar_server(self, host1: str, host2: str, threshold: int = 3) -> bool:
        """
        [CHANGE] Проверяет, относятся ли два сервера к одной подсети.
        Ранее сравнивались части fingerprint-хеша (бессмысленно), а условие
        len(parts) >= 6 никогда не выполнялось для IPv4 (макс. 4 октета).

        Теперь: IPv4 сравнивается по /24 (первые 3 октета), IPv6 — по /48.
        threshold оставлен для совместимости сигнатуры.
        """
        if not host1 or not host2:
            return False
        if host1 == host2:
            return True

        try:
            ip1 = ipaddress.ip_address(host1)
            ip2 = ipaddress.ip_address(host2)
        except ValueError:
            # Домены сравниваем строго
            return host1 == host2

        if ip1.version != ip2.version:
            return False

        try:
            if ip1.version == 4:
                # /24 — первые 3 октета
                net1 = ipaddress.ip_network(f"{host1}/24", strict=False)
                net2 = ipaddress.ip_network(f"{host2}/24", strict=False)
                return net1 == net2
            else:
                # /48 префикс для IPv6
                net1 = ipaddress.ip_network(f"{host1}/48", strict=False)
                net2 = ipaddress.ip_network(f"{host2}/48", strict=False)
                return net1 == net2
        except ValueError:
            return False

    def generate_fingerprint(self, config: str) -> str:
        """
        [CHANGE] Генерирует детерминированный отпечаток через единый ConfigIdentity
        (ранее — собственная независимая реализация).
        """
        return ConfigIdentity.get_fingerprint(config)
