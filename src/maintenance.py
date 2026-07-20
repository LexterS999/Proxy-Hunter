"""
maintenance.py - Служебные операции для CI/CD

Вынесено из inline-скриптов GitHub Actions для тестируемости и поддерживаемости.

Использование:
    python src/maintenance.py remove-inactive   # удалить неактивные каналы
    python src/maintenance.py summary           # показать сводку качества
"""

import sys
import os
import json
import logging
from typing import List
from urllib.parse import urlparse

# Добавляем src/ в путь для импортов
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import get_db

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    """Нормализует URL канала (приводит к виду https://host/path)."""
    url = (url or '').strip()
    if not url:
        return ''
    if not url.startswith('http'):
        url = 'https://t.me/s/' + url.lstrip('/')
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        netloc = parsed.netloc.replace('www.', '')
        path = parsed.path.rstrip('/')
        return f"{parsed.scheme}://{netloc}{path}"
    return url


def remove_inactive_channels(channels_file: str = 'custom_channels.txt') -> int:
    """
    Удаляет неактивные каналы (enabled=0 в БД) из custom_channels.txt.
    Возвращает количество удалённых каналов.
    """
    db = get_db()
    try:
        inactive_urls: List[str] = db.get_inactive_channels()
    except Exception as e:
        print(f'Could not read SQLite: {e}')
        return 0

    inactive_norm = {normalize_url(u) for u in inactive_urls if u}

    if not inactive_norm:
        print('No inactive channels found')
        return 0

    print(f'Found {len(inactive_norm)} inactive channels')

    try:
        with open(channels_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    filtered = []
    removed = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            filtered.append(stripped)
            continue
        if normalize_url(stripped) in inactive_norm:
            removed += 1
            print(f'Removing: {stripped}')
        else:
            filtered.append(stripped)

    with open(channels_file, 'w', encoding='utf-8') as f:
        for line in filtered:
            f.write(line + '\n' if line else '\n')

    print(f'Removed {removed} inactive channels')
    return removed


def show_quality_summary() -> None:
    """Выводит сводку качества последнего запуска из таблицы runs."""
    db = get_db()
    try:
        latest = db.get_latest_run_summary()
    except Exception as e:
        print(f'  ⚠️  Could not read history: {e}')
        return

    if not latest:
        print('  No history data yet (first run)')
        return

    print(f"  Latest run: {latest.get('timestamp')}")
    print(f"  Raw configs:   {latest.get('total_raw', 0)}")
    print(f"  Valid configs: {latest.get('total_valid', 0)}")
    print(f"  Final configs: {latest.get('total_final', 0)}")
    print(f"  Avg score:     {(latest.get('avg_score') or 0):.3f}")
    print(f"  P50 latency:   {(latest.get('p50_latency') or 0):.0f}ms")
    print(f"  P95 latency:   {(latest.get('p95_latency') or 0):.0f}ms")
    print(f"  P99 latency:   {(latest.get('p99_latency') or 0):.0f}ms")
    print(f"  Success rate:  {(latest.get('success_rate') or 0):.1f}%")

    protocols = latest.get('protocols')
    if isinstance(protocols, str):
        try:
            protocols = json.loads(protocols)
        except Exception:
            protocols = {}
    if protocols:
        print('  Protocols:')
        for p, count in protocols.items():
            print(f'    {p}: {count}')


def main():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    if len(sys.argv) < 2:
        print("Usage: python src/maintenance.py {remove-inactive|summary}")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'remove-inactive':
        remove_inactive_channels()
    elif cmd == 'summary':
        show_quality_summary()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
