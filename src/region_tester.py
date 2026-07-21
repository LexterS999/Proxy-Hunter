"""
Региональное тестирование прокси-конфигураций через xray-core.

Проверяет, может ли прокси открыть домен, ЗАБЛОКИРОВАННЫЙ в целевом регионе:
  - RU: rutracker.org (блокировка Роскомнадзора / ТСПУ)
  - CN: google.com (блокировка GFW)
  - IR: twitter.com (блокировка GFI)

Метод: для каждого конфига генерируется временный xray-конфиг,
запускается xray-core как subprocess, и через его SOCKS5 inbound
делается HTTP-запрос к тестовому домену. Если ответ получен →
прокси работает в данном регионе.

Протоколы hysteria2/tuic НЕ поддерживаются xray-core и пропускаются.

Запуск из CLI:
  python src/region_tester.py \
    --test-domain rutracker.org \
    --region RU \
    --input configs/output_simple.txt \
    --output configs/region_test_results.json \
    --top-n 50 \
    --xray-path xray \
    --timeout 15 \
    --max-concurrent 3
"""

import asyncio
import argparse
import json
import logging
import os
import random
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any

try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger(__name__)

# =============================================================================
# Региональные тестовые домены
# =============================================================================
REGION_TEST_DOMAINS: Dict[str, Dict[str, Any]] = {
    'RU': {
        'primary': 'rutracker.org',
        'fallback': ['linkedin.com', 'bbc.com', 'meduza.io', 'dw.com'],
        'whitelisted': ['gosuslugi.ru', 'yandex.ru', 'vk.com', 'mail.ru'],
        'description': 'Домены, заблокированные Роскомнадзором / ТСПУ',
    },
    'CN': {
        'primary': 'google.com',
        'fallback': ['youtube.com', 'twitter.com', 'facebook.com', 'wikipedia.org'],
        'whitelisted': ['baidu.com', 'qq.com', 'taobao.com', 'jd.com'],
        'description': 'Домены, заблокированные GFW (Great Firewall)',
    },
    'IR': {
        'primary': 'twitter.com',
        'fallback': ['telegram.org', 'youtube.com', 'instagram.com', 'facebook.com'],
        'whitelisted': ['aparat.com', 'digikala.com', 'snapp.ir', 'divar.ir'],
        'description': 'Домены, заблокированные GFI (Government Filtering Infrastructure)',
    },
    'GENERIC': {
        'primary': 'google.com',
        'fallback': ['cloudflare.com', 'github.com', 'wikipedia.org'],
        'whitelisted': ['example.com', 'iana.org'],
        'description': 'Базовая проверка доступности',
    },
}

# Протоколы, которые xray-core НЕ поддерживает (нужны отдельные бинарники)
XRAY_UNSUPPORTED_PROTOCOLS = {'hysteria2', 'hy2', 'tuic'}


@dataclass
class RegionTestResult:
    """Результат тестирования одного конфига."""
    config: str = ""
    server: str = ""
    port: int = 0
    protocol: str = ""
    tested: bool = False
    skipped: bool = False
    success: bool = False
    latency_ms: float = -1.0
    status_code: int = 0
    error: str = ""
    test_domain: str = ""
    region: str = ""
    reason: str = ""


class RegionConnectivityTester:
    """
    Тестирует прокси-конфигурации на доступность региональных
    заблокированных доменов через xray-core.
    """

    def __init__(
        self,
        region: str = "RU",
        test_domain: Optional[str] = None,
        xray_path: str = "xray",
        timeout: float = 15.0,
        max_concurrent: int = 3,
        shutdown_event: Optional[asyncio.Event] = None,
    ):
        self.region = region.upper()
        if self.region not in REGION_TEST_DOMAINS:
            self.region = 'GENERIC'

        region_info = REGION_TEST_DOMAINS[self.region]
        self.test_domain = test_domain or region_info['primary']
        self.fallback_domains = region_info['fallback']
        self.xray_path = xray_path
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.shutdown_event = shutdown_event or asyncio.Event()

        self._sem = asyncio.Semaphore(max_concurrent)
        self._port_counter = 10800
        self._port_lock = asyncio.Lock()

        self._stats = {
            'tested': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
        }

    async def _next_port(self) -> int:
        """Выделяет следующий свободный порт для xray inbound."""
        async with self._port_lock:
            self._port_counter += 1
            if self._port_counter > 10999:
                self._port_counter = 10800
            return self._port_counter

    def _is_shutdown(self) -> bool:
        return self.shutdown_event.is_set()

    # =========================================================================
    # Генерация xray-конфига
    # =========================================================================
    def _build_xray_config(self, parsed: Dict[str, Any], inbound_port: int) -> Optional[Dict]:
        """
        Генерирует полный xray-конфиг для тестирования.
        Inbound: SOCKS5 на 127.0.0.1:<inbound_port>
        Outbound: прокси из parsed config
        """
        protocol = parsed.get('protocol', '').lower()
        server = parsed.get('server', parsed.get('address', ''))
        port = int(parsed.get('port', 443))

        if not server or not port:
            return None

        outbound = self._build_outbound(parsed, protocol, server, port)
        if outbound is None:
            return None

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": inbound_port,
                "protocol": "socks",
                "listen": "127.0.0.1",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "ip": "127.0.0.1",
                },
            }],
            "outbounds": [outbound, {
                "protocol": "freedom",
                "tag": "direct",
            }],
        }

    def _build_outbound(
        self, parsed: Dict, protocol: str, server: str, port: int
    ) -> Optional[Dict]:
        """Строит outbound-секцию xray-конфига по протоколу."""

        if protocol == 'vless':
            return self._build_vless(parsed, server, port)
        elif protocol == 'vmess':
            return self._build_vmess(parsed, server, port)
        elif protocol == 'trojan':
            return self._build_trojan(parsed, server, port)
        elif protocol in ('shadowsocks', 'ss'):
            return self._build_shadowsocks(parsed, server, port)
        elif protocol == 'socks':
            return self._build_socks(parsed, server, port)
        elif protocol == 'http':
            return self._build_http(parsed, server, port)
        else:
            return None

    def _build_vless(self, parsed: Dict, server: str, port: int) -> Dict:
        security = parsed.get('security', 'none')
        user_id = parsed.get('uuid', parsed.get('id', ''))
        flow = parsed.get('flow', '')
        encryption = parsed.get('encryption', 'none')

        user: Dict[str, Any] = {"id": user_id}
        if flow:
            user["flow"] = flow
        if encryption and encryption != 'none':
            user["encryption"] = encryption

        outbound: Dict[str, Any] = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [user],
                }],
            },
            "streamSettings": self._build_stream_settings(parsed, security),
        }
        return outbound

    def _build_vmess(self, parsed: Dict, server: str, port: int) -> Dict:
        user_id = parsed.get('uuid', parsed.get('id', ''))
        alter_id = int(parsed.get('aid', parsed.get('alterId', 0)))
        security = parsed.get('security', 'auto')

        outbound: Dict[str, Any] = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": user_id,
                        "alterId": alter_id,
                        "security": security,
                    }],
                }],
            },
            "streamSettings": self._build_stream_settings(parsed, parsed.get('tls', 'none')),
        }
        return outbound

    def _build_trojan(self, parsed: Dict, server: str, port: int) -> Dict:
        password = parsed.get('password', '')

        outbound: Dict[str, Any] = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": password,
                }],
            },
            "streamSettings": self._build_stream_settings(parsed, 'tls'),
        }
        return outbound

    def _build_shadowsocks(self, parsed: Dict, server: str, port: int) -> Dict:
        password = parsed.get('password', '')
        method = parsed.get('method', parsed.get('cipher', 'aes-256-gcm'))

        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": password,
                    "method": method,
                }],
            },
        }

    def _build_socks(self, parsed: Dict, server: str, port: int) -> Dict:
        username = parsed.get('username', '')
        password = parsed.get('password', '')

        server_cfg: Dict[str, Any] = {
            "address": server,
            "port": port,
        }
        if username:
            server_cfg["users"] = [{"user": username, "pass": password}]

        return {
            "protocol": "socks",
            "settings": {
                "servers": [server_cfg],
            },
        }

    def _build_http(self, parsed: Dict, server: str, port: int) -> Dict:
        username = parsed.get('username', '')
        password = parsed.get('password', '')

        server_cfg: Dict[str, Any] = {
            "address": server,
            "port": port,
        }
        if username:
            server_cfg["users"] = [{"user": username, "pass": password}]

        return {
            "protocol": "http",
            "settings": {
                "servers": [server_cfg],
            },
        }

    def _build_stream_settings(self, parsed: Dict, security: str) -> Dict:
        """Строит streamSettings для vless/vmess/trojan."""
        network = parsed.get('network', parsed.get('transport', 'tcp'))
        stream: Dict[str, Any] = {"network": network}

        if security in ('tls', 'reality'):
            stream["security"] = security

            if security == 'tls':
                tls_settings: Dict[str, Any] = {}
                sni = parsed.get('sni', parsed.get('servername', ''))
                if sni:
                    tls_settings["serverName"] = sni
                tls_settings["allowInsecure"] = True
                alpn = parsed.get('alpn', '')
                if alpn:
                    tls_settings["alpn"] = alpn.split(',') if isinstance(alpn, str) else alpn
                stream["tlsSettings"] = tls_settings

            elif security == 'reality':
                reality_settings: Dict[str, Any] = {
                    "allowInsecure": True,
                }
                sni = parsed.get('sni', parsed.get('servername', ''))
                if sni:
                    reality_settings["serverName"] = sni
                pbk = parsed.get('pbk', parsed.get('publicKey', ''))
                if pbk:
                    reality_settings["publicKey"] = pbk
                sid = parsed.get('sid', parsed.get('shortId', ''))
                if sid:
                    reality_settings["shortId"] = sid
                fp = parsed.get('fp', parsed.get('fingerprint', 'chrome'))
                reality_settings["fingerprint"] = fp
                spider_x = parsed.get('spx', parsed.get('spiderX', ''))
                if spider_x:
                    reality_settings["spiderX"] = spider_x
                stream["realitySettings"] = reality_settings

        # Transport-specific settings
        if network == 'ws':
            ws_settings: Dict[str, Any] = {}
            host = parsed.get('host', '')
            path = parsed.get('path', '/')
            if host:
                ws_settings["headers"] = {"Host": host}
            ws_settings["path"] = path
            stream["wsSettings"] = ws_settings

        elif network == 'grpc':
            grpc_settings: Dict[str, Any] = {}
            service_name = parsed.get('serviceName', parsed.get('grpc_service', ''))
            if service_name:
                grpc_settings["serviceName"] = service_name
            stream["grpcSettings"] = grpc_settings

        elif network == 'tcp':
            tcp_settings: Dict[str, Any] = {}
            header_type = parsed.get('headerType', parsed.get('type', 'none'))
            if header_type and header_type != 'none':
                tcp_settings["header"] = {"type": header_type}
                if header_type == 'http':
                    http_host = parsed.get('host', '')
                    http_path = parsed.get('path', '/')
                    tcp_settings["header"]["request"] = {
                        "version": "1.1",
                        "method": "GET",
                        "path": http_path if isinstance(http_path, list) else [http_path],
                        "headers": {
                            "Host": http_host if isinstance(http_host, list) else [http_host],
                            "User-Agent": ["Mozilla/5.0"],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                        },
                    }
            stream["tcpSettings"] = tcp_settings

        elif network == 'kcp':
            kcp_settings: Dict[str, Any] = {
                "mtu": 1350,
                "tti": 50,
                "uplinkCapacity": 12,
                "downlinkCapacity": 100,
                "congestion": False,
                "readBufferSize": 2,
                "writeBufferSize": 2,
            }
            header_type = parsed.get('headerType', parsed.get('type', 'none'))
            if header_type and header_type != 'none':
                kcp_settings["header"] = {"type": header_type}
            stream["kcpSettings"] = kcp_settings

        elif network == 'http':
            http_settings: Dict[str, Any] = {}
            host = parsed.get('host', '')
            path = parsed.get('path', '/')
            if host:
                http_settings["host"] = host if isinstance(host, list) else [host]
            http_settings["path"] = path
            stream["httpSettings"] = http_settings

        elif network == 'quic':
            quic_settings: Dict[str, Any] = {}
            quic_security = parsed.get('quicSecurity', 'none')
            quic_key = parsed.get('key', '')
            header_type = parsed.get('headerType', 'none')
            quic_settings["security"] = quic_security
            quic_settings["key"] = quic_key
            if header_type and header_type != 'none':
                quic_settings["header"] = {"type": header_type}
            stream["quicSettings"] = quic_settings

        return stream

    # =========================================================================
    # Тестирование одного конфига
    # =========================================================================
    async def test_config(self, parsed: Dict[str, Any]) -> RegionTestResult:
        """Тестирует один конфиг. Вызывается с семафором."""
        async with self._sem:
            return await self._test_one(parsed)

    async def _test_one(self, parsed: Dict[str, Any]) -> RegionTestResult:
        """Внутренний метод: тест одного конфига через xray-core."""
        config_str = parsed.get('config', '')
        protocol = parsed.get('protocol', '').lower()
        server = parsed.get('server', parsed.get('address', ''))
        port = int(parsed.get('port', 443))

        result = RegionTestResult(
            config=config_str,
            server=server,
            port=port,
            protocol=protocol,
            test_domain=self.test_domain,
            region=self.region,
        )

        if self._is_shutdown():
            result.skipped = True
            result.reason = 'shutdown_requested'
            return result

        # Пропускаем протоколы, не поддерживаемые xray-core
        if protocol in XRAY_UNSUPPORTED_PROTOCOLS:
            result.skipped = True
            result.reason = f'{protocol} not supported by xray-core'
            self._stats['skipped'] += 1
            return result

        # Проверяем наличие xray
        if not await self._xray_available():
            result.skipped = True
            result.reason = 'xray-core not found'
            self._stats['skipped'] += 1
            return result

        # Генерируем xray-конфиг
        inbound_port = await self._next_port()
        xray_config = self._build_xray_config(parsed, inbound_port)
        if xray_config is None:
            result.skipped = True
            result.reason = 'could not build xray config'
            self._stats['skipped'] += 1
            return result

        # Записываем временный конфиг
        config_path = os.path.join(
            tempfile.gettempdir(),
            f"xray_test_{inbound_port}_{int(time.time()*1000)}.json"
        )
        try:
            with open(config_path, 'w') as f:
                json.dump(xray_config, f)
        except OSError as e:
            result.error = f'write config failed: {e}'
            self._stats['errors'] += 1
            return result

        proc = None
        try:
            # Запускаем xray
            proc = await asyncio.create_subprocess_exec(
                self.xray_path, 'run', '-c', config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # Ждём старта xray (даём 1.5 сек на инициализацию)
            await asyncio.sleep(1.5)

            if proc.returncode is not None:
                result.tested = True
                result.success = False
                result.error = f'xray exited with code {proc.returncode}'
                self._stats['tested'] += 1
                self._stats['failed'] += 1
                return result

            # Тестируем подключение через xray SOCKS5
            success, latency, status_code, error = await self._fetch_through_socks(
                inbound_port, self.test_domain
            )

            # Если основной домен не ответил, пробуем fallback
            if not success and self.fallback_domains:
                for fallback in self.fallback_domains[:2]:
                    if self._is_shutdown():
                        break
                    success, latency, status_code, error = await self._fetch_through_socks(
                        inbound_port, fallback
                    )
                    if success:
                        result.test_domain = fallback
                        break

            result.tested = True
            result.success = success
            result.latency_ms = latency
            result.status_code = status_code
            result.error = error

            self._stats['tested'] += 1
            if success:
                self._stats['passed'] += 1
            else:
                self._stats['failed'] += 1

            return result

        except Exception as e:
            result.tested = True
            result.success = False
            result.error = str(e)
            self._stats['tested'] += 1
            self._stats['errors'] += 1
            return result

        finally:
            # Останавливаем xray
            if proc is not None and proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass

            # Удаляем временный конфиг
            try:
                os.unlink(config_path)
            except OSError:
                pass

    async def _fetch_through_socks(
        self, port: int, domain: str
    ) -> Tuple[bool, float, int, str]:
        """
        Делает HTTP-запрос через SOCKS5-прокси (xray inbound).
        Возвращает (успех, задержка_мс, статус_код, ошибка).
        """
        if aiohttp is None:
            return False, -1.0, 0, 'aiohttp not installed'

        proxy_url = f'socks5://127.0.0.1:{port}'
        url = f'https://{domain}/'

        start = time.monotonic()
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            client_timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=self.timeout / 2,
            )
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=client_timeout,
            ) as session:
                async with session.get(
                    url,
                    proxy=proxy_url,
                    allow_redirects=True,
                    max_redirects=5,
                ) as resp:
                    # Читаем тело (минимум 1 КБ для подтверждения)
                    body = await resp.read()
                    latency = (time.monotonic() - start) * 1000
                    success = resp.status < 500 and len(body) > 0
                    return success, latency, resp.status, ''

        except asyncio.TimeoutError:
            latency = (time.monotonic() - start) * 1000
            return False, latency, 0, 'timeout'
        except aiohttp.ClientError as e:
            latency = (time.monotonic() - start) * 1000
            return False, latency, 0, f'client_error: {type(e).__name__}'
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return False, latency, 0, str(e)

    async def _xray_available(self) -> bool:
        """Проверяет доступность xray-core."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.xray_path, 'version',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return False

    # =========================================================================
    # Пакетное тестирование
    # =========================================================================
    async def test_batch(
        self, configs: List[Dict[str, Any]]
    ) -> List[RegionTestResult]:
        """Тестирует список конфигов с ограниченной конкурентностью."""
        if not configs:
            return []

        tasks = [self.test_config(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final: List[RegionTestResult] = []
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                final.append(RegionTestResult(
                    config=configs[idx].get('config', ''),
                    server=configs[idx].get('server', ''),
                    port=int(configs[idx].get('port', 0)),
                    protocol=configs[idx].get('protocol', ''),
                    tested=True,
                    success=False,
                    error=str(res),
                    test_domain=self.test_domain,
                    region=self.region,
                ))
                self._stats['errors'] += 1
            else:
                final.append(res)

        return final

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def export_results(
        self, results: List[RegionTestResult]
    ) -> Dict[str, Any]:
        """Экспортирует результаты в JSON-совместимый dict."""
        return {
            'region': self.region,
            'test_domain': self.test_domain,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'stats': self.get_stats(),
            'results': [asdict(r) for r in results],
        }


# =============================================================================
# Парсинг URI для CLI-режима
# =============================================================================
def parse_uri_for_test(uri: str) -> Optional[Dict[str, Any]]:
    """Парсит URI-строку в dict для тестирования."""
    from urllib.parse import urlparse, parse_qs, unquote
    import base64

    uri = uri.strip()
    if not uri:
        return None

    try:
        if uri.startswith('vless://'):
            return _parse_vless_uri(uri)
        elif uri.startswith('vmess://'):
            return _parse_vmess_uri(uri)
        elif uri.startswith('trojan://'):
            return _parse_trojan_uri(uri)
        elif uri.startswith(('ss://', 'shadowsocks://')):
            return _parse_ss_uri(uri)
        elif uri.startswith('socks://'):
            return _parse_socks_uri(uri)
        elif uri.startswith('http://') or uri.startswith('https://'):
            return _parse_http_uri(uri)
        elif uri.startswith(('hysteria2://', 'hy2://')):
            return {'config': uri, 'protocol': 'hysteria2', 'server': '', 'port': 0}
        elif uri.startswith('tuic://'):
            return {'config': uri, 'protocol': 'tuic', 'server': '', 'port': 0}
    except Exception as e:
        logger.debug(f"Failed to parse URI: {e}")

    return None


def _parse_vless_uri(uri: str) -> Dict[str, Any]:
    from urllib.parse import urlparse, parse_qs, unquote
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    uuid = parsed.username or parsed.netloc.split('@')[0] if '@' in parsed.netloc else parsed.netloc.split(':')[0]
    server = parsed.hostname or ''
    port = parsed.port or 443

    result: Dict[str, Any] = {
        'config': uri,
        'protocol': 'vless',
        'server': server,
        'port': port,
        'uuid': uuid,
        'security': params.get('security', ['none'])[0],
        'network': params.get('type', ['tcp'])[0],
        'flow': params.get('flow', [''])[0],
        'encryption': params.get('encryption', ['none'])[0],
        'sni': params.get('sni', [''])[0],
        'host': params.get('host', [''])[0],
        'path': params.get('path', ['/'])[0],
        'fp': params.get('fp', ['chrome'])[0],
        'pbk': params.get('pbk', [''])[0],
        'sid': params.get('sid', [''])[0],
        'spx': params.get('spx', [''])[0],
        'alpn': params.get('alpn', [''])[0],
        'serviceName': params.get('serviceName', [''])[0],
        'headerType': params.get('headerType', ['none'])[0],
    }
    return result


def _parse_vmess_uri(uri: str) -> Dict[str, Any]:
    import base64, json
    from urllib.parse import urlparse
    b64_part = uri.replace('vmess://', '')
    padding = 4 - len(b64_part) % 4
    if padding != 4:
        b64_part += '=' * padding
    decoded = base64.b64decode(b64_part).decode('utf-8')
    data = json.loads(decoded)

    return {
        'config': uri,
        'protocol': 'vmess',
        'server': data.get('add', ''),
        'port': int(data.get('port', 443)),
        'uuid': data.get('id', ''),
        'aid': int(data.get('aid', 0)),
        'security': data.get('scy', 'auto'),
        'network': data.get('net', 'tcp'),
        'tls': data.get('tls', 'none'),
        'sni': data.get('sni', ''),
        'host': data.get('host', ''),
        'path': data.get('path', '/'),
        'alpn': data.get('alpn', ''),
        'fp': data.get('fp', ''),
    }


def _parse_trojan_uri(uri: str) -> Dict[str, Any]:
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    return {
        'config': uri,
        'protocol': 'trojan',
        'server': parsed.hostname or '',
        'port': parsed.port or 443,
        'password': parsed.username or '',
        'security': 'tls',
        'network': params.get('type', ['tcp'])[0],
        'sni': params.get('sni', [''])[0],
        'host': params.get('host', [''])[0],
        'path': params.get('path', ['/'])[0],
        'alpn': params.get('alpn', [''])[0],
        'fp': params.get('fp', [''])[0],
        'serviceName': params.get('serviceName', [''])[0],
    }


def _parse_ss_uri(uri: str) -> Dict[str, Any]:
    import base64
    from urllib.parse import urlparse, parse_qs, unquote

    if uri.startswith('ss://'):
        uri = uri[5:]
    elif uri.startswith('shadowsocks://'):
        uri = uri[14:]

    # Формат: base64(method:password)@server:port#tag
    # или: base64(method:password@server:port)#tag
    if '@' in uri:
        userinfo, hostpart = uri.rsplit('@', 1)
        # userinfo может быть base64
        try:
            padding = 4 - len(userinfo) % 4
            if padding != 4:
                userinfo += '=' * padding
            decoded = base64.b64decode(userinfo).decode('utf-8')
            method, password = decoded.split(':', 1)
        except Exception:
            method, password = 'aes-256-gcm', userinfo

        tag = ''
        if '#' in hostpart:
            hostpart, tag = hostpart.split('#', 1)

        server, port_str = hostpart.rsplit(':', 1)
        port = int(port_str)

        return {
            'config': f'ss://{uri}',
            'protocol': 'shadowsocks',
            'server': server,
            'port': port,
            'method': method,
            'password': password,
        }
    else:
        # Полностью base64
        tag = ''
        if '#' in uri:
            uri, tag = uri.split('#', 1)
        try:
            padding = 4 - len(uri) % 4
            if padding != 4:
                uri += '=' * padding
            decoded = base64.b64decode(uri).decode('utf-8')
            # method:password@server:port
            userinfo, hostpart = decoded.rsplit('@', 1)
            method, password = userinfo.split(':', 1)
            server, port_str = hostpart.rsplit(':', 1)
            return {
                'config': f'ss://{uri}',
                'protocol': 'shadowsocks',
                'server': server,
                'port': int(port_str),
                'method': method,
                'password': password,
            }
        except Exception:
            return {'config': uri, 'protocol': 'shadowsocks', 'server': '', 'port': 0}


def _parse_socks_uri(uri: str) -> Dict[str, Any]:
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    return {
        'config': uri,
        'protocol': 'socks',
        'server': parsed.hostname or '',
        'port': parsed.port or 1080,
        'username': parsed.username or '',
        'password': parsed.password or '',
    }


def _parse_http_uri(uri: str) -> Dict[str, Any]:
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    return {
        'config': uri,
        'protocol': 'http',
        'server': parsed.hostname or '',
        'port': parsed.port or 80,
        'username': parsed.username or '',
        'password': parsed.password or '',
    }


# =============================================================================
# CLI-точка входа
# =============================================================================
async def run_cli(args: argparse.Namespace) -> None:
    """Запуск регионального тестирования из CLI."""
    # Читаем конфиги из входного файла
    configs: List[Dict[str, Any]] = []
    if args.input and os.path.exists(args.input):
        with open(args.input, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parsed = parse_uri_for_test(line)
                if parsed:
                    configs.append(parsed)

    if not configs:
        print("⚠️ No configs to test")
        return

    # Берём топ-N
    top_n = int(args.top_n)
    if top_n > 0 and len(configs) > top_n:
        configs = configs[:top_n]

    print(f"📋 Testing {len(configs)} configs against {args.test_domain} ({args.region})")

    tester = RegionConnectivityTester(
        region=args.region,
        test_domain=args.test_domain,
        xray_path=args.xray_path,
        timeout=args.timeout,
        max_concurrent=args.max_concurrent,
    )

    results = await tester.test_batch(configs)

    # Выводим результаты
    stats = tester.get_stats()
    print(f"\n{'='*60}")
    print(f"🌐 Region Test Results: {args.region} → {args.test_domain}")
    print(f"{'='*60}")
    print(f"  Tested:  {stats['tested']}")
    print(f"  Passed:  {stats['passed']}")
    print(f"  Failed:  {stats['failed']}")
    print(f"  Skipped: {stats['skipped']}")
    print(f"  Errors:  {stats['errors']}")
    if stats['tested'] > 0:
        print(f"  Pass rate: {stats['passed']/stats['tested']*100:.1f}%")
    print(f"{'='*60}")

    for r in results:
        if r.skipped:
            print(f"  ⏭️  [{r.protocol}] {r.server}:{r.port} — skipped ({r.reason})")
        elif r.success:
            print(f"  ✅ [{r.protocol}] {r.server}:{r.port} — {r.latency_ms:.0f}ms (HTTP {r.status_code})")
        else:
            print(f"  ❌ [{r.protocol}] {r.server}:{r.port} — {r.error or 'failed'}")

    # Сохраняем результаты
    if args.output:
        export = tester.export_results(results)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description='Region connectivity tester for Proxy-Hunter')
    parser.add_argument('--test-domain', required=True, help='Domain to test (blocked in target region)')
    parser.add_argument('--region', default='RU', choices=['RU', 'CN', 'IR', 'GENERIC'])
    parser.add_argument('--input', default='configs/output_simple.txt', help='Input file with proxy URIs')
    parser.add_argument('--output', default='configs/region_test_results.json', help='Output JSON file')
    parser.add_argument('--top-n', type=int, default=50, help='Number of top configs to test')
    parser.add_argument('--xray-path', default='xray', help='Path to xray binary')
    parser.add_argument('--timeout', type=float, default=15.0, help='Timeout per test (seconds)')
    parser.add_argument('--max-concurrent', type=int, default=3, help='Max concurrent xray instances')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    asyncio.run(run_cli(args))


if __name__ == '__main__':
    main()
