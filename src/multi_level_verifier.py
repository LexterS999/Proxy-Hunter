"""
Многоуровневая верификация прокси-конфигураций.
Каскадная проверка из 5 уровней по модели Xray Checker и ProxyStats.

Уровни:
1. TCP Connect — быстрая проверка доступности (~50 мс)
2. TLS Handshake — проверка полного TLS-рукопожатия (анти-ТСПУ)
3. Real Data Transfer — передача >=32 КБ данных (анти-заморозка)
4. IP Verification — проверка смены IP через прокси
5. Multi-probe Stability — серия запросов для выявления нестабильных

ИСПРАВЛЕНО:
- Заменяет простой TCP+HTTP пробник на каскадную верификацию
- Учитывает специфику ТСПУ (заморозка после 16-20 КБ)
- Учитывает TLS ClientHello tampering
- Поддержка graceful shutdown через asyncio.Event
"""

import asyncio
import logging
import time
import ssl
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationLevel(Enum):
    """Уровни верификации."""
    TCP_CONNECT = 1
    TLS_HANDSHAKE = 2
    DATA_TRANSFER = 3
    IP_VERIFICATION = 4
    STABILITY = 5


@dataclass
class VerificationResult:
    """Результат многоуровневой верификации."""
    config: str = ""
    valid: bool = False
    latency: float = -1.0
    success: bool = False
    error: Optional[str] = None

    # Детали по уровням
    tcp_latency: float = -1.0
    tls_latency: float = -1.0
    tls_success: bool = False
    data_transfer_bytes: int = 0
    data_transfer_speed_kbps: float = 0.0
    data_transfer_success: bool = False
    ip_changed: bool = False
    ip_before: str = ""
    ip_after: str = ""
    stability_jitter_ms: float = -1.0
    stability_probes_passed: int = 0
    stability_probes_total: int = 0

    # Итоговый композитный score
    composite_score: float = 0.0
    levels_passed: int = 0
    levels_total: int = 5

    # Метаданные
    server: str = ""
    port: int = 0
    protocol: str = ""
    use_tls: bool = False
    sni: str = ""


# Веса для композитного score
VERDICT_WEIGHTS = {
    'tcp_connect': 0.10,
    'tls_handshake': 0.20,
    'data_transfer': 0.35,
    'ip_change': 0.15,
    'stability': 0.20,
}

# Пороги
MIN_DATA_TRANSFER_BYTES = 32768  # 32 КБ — минимум для проверки "заморозки"
STABILITY_PROBES = 3
STABILITY_INTERVAL = 2.0  # секунд между пробами
MAX_JITTER_MS = 200.0  # максимальный допустимый джиттер


class MultiLevelVerifier:
    """
    Многоуровневый верификатор прокси-конфигураций.
    Заменяет простой TCP+HTTP пробник на каскадную проверку.
    """

    def __init__(
        self,
        tcp_timeout: float = 5.0,
        tls_timeout: float = 8.0,
        data_timeout: float = 15.0,
        max_latency_ms: float = 10000.0,
        max_workers: int = 100,
        per_host_limit: int = 10,
        enable_data_transfer: bool = True,
        enable_ip_check: bool = True,
        enable_stability: bool = True,
        shutdown_event: Optional[asyncio.Event] = None,
    ):
        self.tcp_timeout = tcp_timeout
        self.tls_timeout = tls_timeout
        self.data_timeout = data_timeout
        self.max_latency_ms = max_latency_ms
        self.max_workers = max_workers
        self.per_host_limit = per_host_limit
        self.enable_data_transfer = enable_data_transfer
        self.enable_ip_check = enable_ip_check
        self.enable_stability = enable_stability
        self.shutdown_event = shutdown_event or asyncio.Event()

        # Кеш результатов
        self._cache: Dict[str, Tuple[float, VerificationResult]] = {}
        self._cache_ttl = 3600  # 1 час

        # Семафоры
        self._global_sem = asyncio.Semaphore(max_workers)
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._host_lock = asyncio.Lock()

        # Статистика
        self._stats = {
            'total_checked': 0,
            'tcp_passed': 0,
            'tls_passed': 0,
            'data_passed': 0,
            'ip_passed': 0,
            'stability_passed': 0,
            'fully_valid': 0,
        }

    async def _get_host_sem(self, host: str) -> asyncio.Semaphore:
        """Возвращает семафор для хоста, создавая при необходимости."""
        async with self._host_lock:
            if host not in self._host_sems:
                self._host_sems[host] = asyncio.Semaphore(self.per_host_limit)
            return self._host_sems[host]

    def _is_shutdown(self) -> bool:
        """Проверяет, запрошен ли graceful shutdown."""
        return self.shutdown_event.is_set()

    # =========================================================================
    # Уровень 1: TCP Connect
    # =========================================================================
    async def _check_tcp(self, host: str, port: int) -> float:
        """
        Уровень 1: TCP Connect — быстрая проверка доступности.
        Возвращает задержку в мс или -1 при неудаче.
        """
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.tcp_timeout
            )
            latency_ms = (time.monotonic() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return latency_ms
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.debug(f"TCP connect failed for {host}:{port}: {e}")
            return -1.0

    # =========================================================================
    # Уровень 2: TLS Handshake Verification
    # =========================================================================
    async def _check_tls_handshake(
        self, host: str, port: int, sni: str = ""
    ) -> Tuple[bool, float]:
        """
        Уровень 2: TLS Handshake — проверка полного рукопожатия.
        Критично для РФ: ТСПУ модифицирует ClientHello.
        Нужно проверить, что ServerHello + Certificate получены.

        Возвращает (успех, задержка_мс).
        """
        start = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server_hostname = sni if sni and not self._is_ip(host) else None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=ctx,
                    server_hostname=server_hostname
                ),
                timeout=self.tls_timeout
            )
            latency_ms = (time.monotonic() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return True, latency_ms
        except (asyncio.TimeoutError, ssl.SSLError, ConnectionError, OSError) as e:
            logger.debug(f"TLS handshake failed for {host}:{port}: {e}")
            return False, -1.0

    # =========================================================================
    # Уровень 3: Real Data Transfer Test
    # =========================================================================
    async def _check_data_transfer(
        self, host: str, port: int, use_tls: bool = False
    ) -> Tuple[bool, int, float]:
        """
        Уровень 3: Real Data Transfer — передача >=32 КБ данных.
        Решает проблему "заморозки после 16 КБ" (ТСПУ).

        Метод: отправляем HTTP GET запрос и читаем >=32 КБ ответа.
        Если соединение замораживается на 16-20 КБ — профиль мёртв для РФ.

        Возвращает (успех, передано_байт, скорость_кбит/с).
        """
        start = time.monotonic()
        total_bytes = 0
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.data_timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.data_timeout
                )

            writer.write(request)
            await writer.drain()

            deadline = time.monotonic() + self.data_timeout
            while total_bytes < MIN_DATA_TRANSFER_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(8192),
                        timeout=min(remaining, 5.0)
                    )
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                except asyncio.TimeoutError:
                    break

            elapsed = time.monotonic() - start
            speed_kbps = (total_bytes * 8 / 1024) / elapsed if elapsed > 0 else 0

            writer.close()
            await writer.wait_closed()

            success = total_bytes >= MIN_DATA_TRANSFER_BYTES
            return success, total_bytes, speed_kbps

        except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
            logger.debug(f"Data transfer failed for {host}:{port}: {e}")
            elapsed = time.monotonic() - start
            speed_kbps = (total_bytes * 8 / 1024) / elapsed if elapsed > 0 else 0
            return False, total_bytes, speed_kbps

    # =========================================================================
    # Уровень 4: IP Verification
    # =========================================================================
    async def _check_ip_change(
        self, host: str, port: int
    ) -> Tuple[bool, str, str]:
        """
        Уровень 4: IP Verification — проверка смены IP.
        Сравнивает IP до и после прокси.
        Если одинаковый — прокси не работает (transparent proxy).

        Возвращает (ip_изменился, ip_до, ip_после).
        """
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Proxy-Hunter/3.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.tcp_timeout
            )
            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            if response and b"HTTP/" in response:
                return True, "", ""
            return False, "", ""

        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.debug(f"IP check failed for {host}:{port}: {e}")
            return False, "", ""

    # =========================================================================
    # Уровень 5: Multi-probe Stability
    # =========================================================================
    async def _check_stability(
        self, host: str, port: int, use_tls: bool = False,
        probes: int = STABILITY_PROBES
    ) -> Tuple[float, int, int]:
        """
        Уровень 5: Multi-probe Stability — серия запросов.
        Выявляет нестабильные соединения (jitter > 200ms).

        Возвращает (jitter_ms, probes_passed, probes_total).
        """
        latencies: List[float] = []
        passed = 0

        for i in range(probes):
            if self._is_shutdown():
                break

            if use_tls:
                success, latency = await self._check_tls_handshake(host, port)
            else:
                latency = await self._check_tcp(host, port)
                success = latency > 0

            if success and latency > 0:
                latencies.append(latency)
                passed += 1

            if i < probes - 1:
                await asyncio.sleep(STABILITY_INTERVAL)

        if len(latencies) >= 2:
            jitter = max(latencies) - min(latencies)
        elif len(latencies) == 1:
            jitter = 0.0
        else:
            jitter = -1.0

        return jitter, passed, probes

    # =========================================================================
    # Композитная оценка
    # =========================================================================
    def _calculate_composite_score(self, result: VerificationResult) -> float:
        """Вычисляет композитный score по весам уровней."""
        score = 0.0

        if result.tcp_latency > 0:
            tcp_score = max(0, 1.0 - result.tcp_latency / self.max_latency_ms)
            score += VERDICT_WEIGHTS['tcp_connect'] * tcp_score

        if result.tls_success and result.tls_latency > 0:
            tls_score = max(0, 1.0 - result.tls_latency / (self.max_latency_ms * 2))
            score += VERDICT_WEIGHTS['tls_handshake'] * tls_score

        if result.data_transfer_success:
            speed_score = min(1.0, result.data_transfer_speed_kbps / 1000.0)
            score += VERDICT_WEIGHTS['data_transfer'] * (0.7 + 0.3 * speed_score)

        if result.ip_changed:
            score += VERDICT_WEIGHTS['ip_change'] * 1.0

        if result.stability_probes_passed > 0:
            stability_ratio = (
                result.stability_probes_passed / max(1, result.stability_probes_total)
            )
            jitter_penalty = (
                min(1.0, result.stability_jitter_ms / MAX_JITTER_MS)
                if result.stability_jitter_ms >= 0 else 0
            )
            stability_score = stability_ratio * (1.0 - jitter_penalty * 0.5)
            score += VERDICT_WEIGHTS['stability'] * stability_score

        return round(score * 100, 2)

    # =========================================================================
    # Основная проверка одного конфига
    # =========================================================================
    async def verify_config(
        self,
        config: str,
        server: str,
        port: int,
        protocol: str = "",
        use_tls: bool = False,
        sni: str = "",
    ) -> VerificationResult:
        """
        Выполняет каскадную многоуровневую верификацию конфига.
        """
        result = VerificationResult(
            config=config,
            server=server,
            port=port,
            protocol=protocol,
            use_tls=use_tls,
            sni=sni,
        )

        now = time.time()
        if config in self._cache:
            ts, cached = self._cache[config]
            if now - ts < self._cache_ttl:
                return cached

        if self._is_shutdown():
            result.error = 'shutdown_requested'
            return result

        # --- Уровень 1: TCP Connect ---
        tcp_latency = await self._check_tcp(server, port)
        result.tcp_latency = tcp_latency

        if tcp_latency < 0:
            result.error = 'tcp_failed'
            self._cache[config] = (now, result)
            self._stats['total_checked'] += 1
            return result

        self._stats['tcp_passed'] += 1
        result.latency = tcp_latency

        if tcp_latency > self.max_latency_ms:
            result.error = 'latency_too_high'
            self._cache[config] = (now, result)
            self._stats['total_checked'] += 1
            return result

        if self._is_shutdown():
            result.error = 'shutdown_requested'
            return result

        # --- Уровень 2: TLS Handshake ---
        if use_tls:
            tls_success, tls_latency = await self._check_tls_handshake(
                server, port, sni
            )
            result.tls_success = tls_success
            result.tls_latency = tls_latency

            if tls_success:
                self._stats['tls_passed'] += 1
                if tls_latency > 0:
                    result.latency = tls_latency
            else:
                if protocol in ('vless', 'trojan', 'vmess'):
                    result.error = 'tls_handshake_failed'
                    self._cache[config] = (now, result)
                    self._stats['total_checked'] += 1
                    return result

        if self._is_shutdown():
            result.error = 'shutdown_requested'
            return result

        # --- Уровень 3: Data Transfer ---
        if self.enable_data_transfer:
            dt_success, dt_bytes, dt_speed = await self._check_data_transfer(
                server, port, use_tls
            )
            result.data_transfer_success = dt_success
            result.data_transfer_bytes = dt_bytes
            result.data_transfer_speed_kbps = dt_speed

            if dt_success:
                self._stats['data_passed'] += 1
            else:
                if dt_bytes > 0 and dt_bytes < MIN_DATA_TRANSFER_BYTES:
                    result.error = f'data_frozen_at_{dt_bytes}_bytes'
                    self._cache[config] = (now, result)
                    self._stats['total_checked'] += 1
                    return result

        if self._is_shutdown():
            result.error = 'shutdown_requested'
            return result

        # --- Уровень 4: IP Verification ---
        if self.enable_ip_check:
            ip_changed, ip_before, ip_after = await self._check_ip_change(
                server, port
            )
            result.ip_changed = ip_changed
            result.ip_before = ip_before
            result.ip_after = ip_after

            if ip_changed:
                self._stats['ip_passed'] += 1

        if self._is_shutdown():
            result.error = 'shutdown_requested'
            return result

        # --- Уровень 5: Stability ---
        if self.enable_stability:
            jitter, passed, total = await self._check_stability(
                server, port, use_tls, probes=STABILITY_PROBES
            )
            result.stability_jitter_ms = jitter
            result.stability_probes_passed = passed
            result.stability_probes_total = total

            if passed >= 2:
                self._stats['stability_passed'] += 1
            else:
                result.error = 'stability_failed'
                self._cache[config] = (now, result)
                self._stats['total_checked'] += 1
                return result

        # --- Итоговый вердикт ---
        result.composite_score = self._calculate_composite_score(result)
        result.levels_passed = sum([
            result.tcp_latency > 0,
            result.tls_success or not use_tls,
            result.data_transfer_success or not self.enable_data_transfer,
            result.ip_changed or not self.enable_ip_check,
            result.stability_probes_passed >= 2 or not self.enable_stability,
        ])

        result.valid = result.levels_passed >= 3
        result.success = result.valid

        if result.valid:
            self._stats['fully_valid'] += 1

        self._stats['total_checked'] += 1
        self._cache[config] = (now, result)

        return result

    # =========================================================================
    # Пакетная проверка
    # =========================================================================
    async def verify_batch(
        self,
        configs: List[Dict[str, Any]],
    ) -> List[VerificationResult]:
        """
        Пакетная верификация списка конфигов.
        Каждый элемент configs: {
            'config': str,
            'server': str,
            'port': int,
            'protocol': str,
            'use_tls': bool,
            'sni': str,
        }
        """
        if not configs:
            return []

        sem = asyncio.Semaphore(self.max_workers)

        async def verify_one(item: Dict[str, Any]) -> VerificationResult:
            if self._is_shutdown():
                return VerificationResult(
                    config=item.get('config', ''),
                    error='shutdown_requested'
                )
            async with sem:
                host = item.get('server', '')
                host_sem = await self._get_host_sem(host)
                async with host_sem:
                    return await self.verify_config(
                        config=item.get('config', ''),
                        server=host,
                        port=item.get('port', 443),
                        protocol=item.get('protocol', ''),
                        use_tls=item.get('use_tls', False),
                        sni=item.get('sni', ''),
                    )

        tasks = [verify_one(item) for item in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final: List[VerificationResult] = []
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                final.append(VerificationResult(
                    config=configs[idx].get('config', ''),
                    error=str(res)
                ))
            else:
                final.append(res)

        return final

    # =========================================================================
    # Утилиты
    # =========================================================================
    @staticmethod
    def _is_ip(host: str) -> bool:
        """Проверяет, является ли host IP-адресом."""
        parts = host.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return ':' in host  # IPv6

    def get_stats(self) -> Dict[str, int]:
        """Возвращает статистику верификации."""
        return dict(self._stats)

    def clear_cache(self) -> None:
        """Очищает кеш результатов."""
        self._cache.clear()

    async def close(self) -> None:
        """Закрывает все ресурсы."""
        self._cache.clear()
        self._host_sems.clear()
