#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Утилиты для красивого и информативного логирования.
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


def print_summary(stats: Dict[str, Any]) -> None:
    """
    Выводит итоговую статистику в виде таблицы.
    """
    border = "═" * 60
    print("\n" + "═" * 60)
    print("  🎯  ИТОГИ РАБОТЫ ПАЙПЛАЙНА")
    print("═" * 60)

    # Общие показатели
    print(f"  📥 Собрано конфигов (сырых):    {stats.get('raw', 0):>8}")
    print(f"  ✅ Валидных конфигов:           {stats.get('valid', 0):>8}")
    print(f"  🔍 Прошли активную проверку:    {stats.get('active_ok', 0):>8}")
    print(f"  🧹 После дедупликации:          {stats.get('deduped', 0):>8}")
    print(f"  📦 В архиве (output_archive):   {stats.get('archive', 0):>8}")
    print(f"  📄 В простом выводе (simple):   {stats.get('simple', 0):>8}")

    # Протоколы
    protocols = stats.get('protocols', {})
    if protocols:
        print("\n  📡  Распределение по протоколам:")
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            print(f"      {proto:>12}: {count:>6}")

    # Качество
    quality = stats.get('quality', {})
    if quality:
        print("\n  📊  Качество конфигов:")
        print(f"      Средний скор:  {quality.get('avg_score', 0):>6.1f}")
        print(f"      Медианный скор: {quality.get('median_score', 0):>6.1f}")
        print(f"      Минимальный:    {quality.get('min_score', 0):>6.1f}")
        print(f"      Максимальный:   {quality.get('max_score', 0):>6.1f}")

    # Каналы
    channels = stats.get('channels', {})
    if channels:
        print("\n  📺  Состояние каналов:")
        print(f"      Активных:       {channels.get('active', 0):>6}")
        print(f"      Восстанавлив.:  {channels.get('recovering', 0):>6}")
        print(f"      Неактивных:     {channels.get('inactive', 0):>6}")
        print(f"      Всего:          {channels.get('total', 0):>6}")

    print("═" * 60 + "\n")
