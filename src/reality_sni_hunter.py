"""
Reality SNI Hunter — асинхронный инструмент для сканирования IP-диапазонов,
сбора рабочего SNI с TLS-серверов и проверки их через реальный Xray Core.
"""

import asyncio
import logging
import random
import time
import tempfile
import os
import json
import subprocess
from typing import List, Dict, Optional
import ipaddress
import ssl
import socket
import aiohttp
from aiohttp import ClientTimeout

from xray_probe import XrayProbe

logger = logging.getLogger(__name__)

class RealitySNIHunter:
    def __init__(self, xray_core_path: str = "xray", timeout: float = 5.0):
        self.xray_core_path = xray_core_path
        self.timeout = timeout
        self.probe = XrayProbe(xray_path=xray_core_path, timeout=timeout)

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
        Проверяет работоспособность SNI через реальный Xray Core.
        Использует XrayProbe для запуска xray с конфигом, где sni подставлен.
        """
        # Создаём конфиг на основе шаблона, заменяя sni и адрес
        config = config_template.copy()
        # Если шаблон пустой, создаём минимальный vless-конфиг
        if not config:
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"auth": "noauth"}}],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": server_ip,
                            "port": 443,
                            "users": [{
                                "id": "00000000-0000-0000-0000-000000000000",
                                "flow": "xtls-rprx-vision",
                                "encryption": "none"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": sni,
                            "publicKey": "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=",
                            "shortId": "6ba85179e30d4fc2",
                            "fingerprint": "chrome"
                        }
                    }
                }],
                "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]}
            }

        # Запускаем XrayProbe
        try:
            result = await self.probe.probe_config(json.dumps(config))
            return result.get('success', False)
        except Exception as e:
            logger.error(f"Xray probe failed for SNI {sni} on {server_ip}: {e}")
            return False

    async def hunt(self, ip_range: str, top_n: int = 20, config_template: Dict = None) -> List[Dict]:
        """
        Основной метод: сканирует IP, собирает SNI, проверяет их через Xray и возвращает топ-N.
        """
        ips = await self.scan_ip_range(ip_range)
        logger.info(f"Found {len(ips)} reachable IPs in range {ip_range}")
        sni_data = await self.collect_sni(ips)
        logger.info(f"Collected {len(sni_data)} SNI entries")
        # Проверяем каждый SNI через реальный Xray
        verified = []
        sem = asyncio.Semaphore(5)  # ограничиваем параллельные проверки
        async def check_entry(entry):
            async with sem:
                sni = entry['sni']
                ip = entry['ip']
                ok = await self.verify_with_xray(sni, ip, config_template or {})
                if ok:
                    return entry
                return None
        tasks = [check_entry(entry) for entry in sni_data]
        results = await asyncio.gather(*tasks)
        verified = [r for r in results if r]
        # Сортируем по надёжности (можно добавить пинг)
        return verified[:top_n]
