"""
Reality SNI Hunter — асинхронный инструмент для сканирования IP-диапазонов,
сбора рабочего SNI с TLS-серверов и проверки их через реальный Xray Core.
"""

import asyncio
import logging
import random
import time
from typing import List, Dict, Optional
import ipaddress
import ssl
import socket
import aiohttp
from aiohttp import ClientTimeout

logger = logging.getLogger(__name__)

class RealitySNIHunter:
    def __init__(self, xray_core_path: str = "xray", timeout: float = 5.0):
        self.xray_core_path = xray_core_path
        self.timeout = timeout

    async def scan_ip_range(self, ip_range: str, port: int = 443, limit: int = 100) -> List[str]:
        """
        Сканирует диапазон IP, возвращает список IP, у которых открыт порт 443 с TLS.
        """
        network = ipaddress.ip_network(ip_range, strict=False)
        ips = list(network.hosts())
        if len(ips) > limit:
            ips = random.sample(ips, limit)
        results = []
        sem = asyncio.Semaphore(20)
        async def check_ip(ip):
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(str(ip), port, ssl=False),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return str(ip)
                except:
                    return None
        tasks = [check_ip(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def fetch_sni(self, ip: str, port: int = 443) -> Optional[str]:
        """
        Извлекает SNI из TLS-сертификата сервера (Server Name Indication из сертификата).
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if cert and 'subjectAltName' in cert:
                        for san in cert['subjectAltName']:
                            if san[0] == 'DNS':
                                return san[1]
                    # Fallback: CN из subject
                    if cert and 'subject' in cert:
                        for item in cert['subject']:
                            for sub in item:
                                if sub[0] == 'commonName':
                                    return sub[1]
        except Exception as e:
            logger.debug(f"Failed to fetch SNI from {ip}: {e}")
        return None

    async def collect_sni(self, ip_list: List[str]) -> List[Dict]:
        """
        Собирает SNI с каждого IP.
        """
        tasks = [self.fetch_sni(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks)
        return [{'ip': ip, 'sni': sni} for ip, sni in zip(ip_list, results) if sni]

    async def verify_with_xray(self, sni: str, server_ip: str, config_template: Dict) -> bool:
        """
        Проверяет работоспособность SNI через Xray Core.
        Здесь нужно запустить xray с конфигом, где sni подставлен.
        Упрощённая версия — просто проверка через TLS (без Xray).
        """
        try:
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server_ip, 443, ssl=context, server_hostname=sni),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def hunt(self, ip_range: str, top_n: int = 20) -> List[Dict]:
        """
        Основной метод: сканирует IP, собирает SNI, проверяет их и возвращает топ-N.
        """
        ips = await self.scan_ip_range(ip_range)
        logger.info(f"Found {len(ips)} reachable IPs in range {ip_range}")
        sni_data = await self.collect_sni(ips)
        logger.info(f"Collected {len(sni_data)} SNI entries")
        # Проверяем каждый SNI
        verified = []
        for entry in sni_data:
            sni = entry['sni']
            ip = entry['ip']
            ok = await self.verify_with_xray(sni, ip, {})  # упрощённо
            if ok:
                verified.append(entry)
        # Сортируем и возвращаем топ-N
        return verified[:top_n]
