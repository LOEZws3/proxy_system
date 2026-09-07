#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Прокси-парсер + чекер с умным обновлением (без проверки Telegram)
Версия: 5.3 (только сбор и пинг)
"""

import sys
import io
import asyncio
import aiohttp
import json
import os
import re
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
import logging

# Исправление кодировки для Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_checker.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

CONFIG = {
    "timeout": 5,  # Уменьшаем таймаут для пинга
    "max_concurrent": 50,
    "test_url": "http://httpbin.org/ip",  # ✅ Простой URL для проверки
    "good_proxies_file": "good_proxies.txt",
    "bad_proxies_file": "bad_proxies.txt",
    "proxies_file": "proxies.txt",
    "check_interval": 60,
    "max_proxy_age_days": 2,
    "min_proxies": 5,
    "sources": [
        # ============ HTTP/HTTPS ============
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/https.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/https.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Proxy-List/main/http.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Proxy-List/main/https.txt",
        
        # ============ SOCKS4 ============
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Proxy-List/main/socks4.txt",
        
        # ============ SOCKS5 ============
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/hendrikbgr/Proxy-List/main/socks5.txt",
        
        # ============ ДОПОЛНИТЕЛЬНЫЕ ============
        "https://api.proxyscrape.com/?request=displayproxies&proxytype=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/?request=displayproxies&proxytype=https&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&limit=1000",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all&limit=1000",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all&limit=1000",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all&limit=1000",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy-list.txt",
        "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies.txt",
    ]
}

# ============================================================
# РАБОТА С ФАЙЛАМИ (С ДАТАМИ)
# ============================================================

def load_proxies_with_dates(filename: str) -> Dict[str, datetime]:
    """Загружает прокси с датами добавления"""
    proxies = {}
    if not os.path.exists(filename):
        return proxies
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if '|' in line:
                    proxy, date_str = line.split('|', 1)
                    try:
                        date_added = datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
                        proxies[proxy] = date_added
                    except:
                        proxies[proxy] = datetime.now()
                else:
                    proxies[line] = datetime.now()
        logger.info(f"📂 Загружено {len(proxies)} прокси с датами из {filename}")
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки {filename}: {e}")
    
    return proxies


def save_proxies_with_dates(proxies: Dict[str, datetime], filename: str):
    """Сохраняет прокси с датами"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for proxy, date_added in sorted(proxies.items()):
                date_str = date_added.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{proxy}|{date_str}\n")
        logger.info(f"💾 Сохранено {len(proxies)} прокси в {filename}")
    except Exception as e:
        logger.error(f"❌ Ошибка сохранения {filename}: {e}")


def remove_old_proxies(proxies: Dict[str, datetime], max_age_days: int) -> int:
    """Удаляет прокси старше указанного количества дней"""
    now = datetime.now()
    cutoff = now - timedelta(days=max_age_days)
    old_proxies = [p for p, d in proxies.items() if d < cutoff]
    
    for p in old_proxies:
        del proxies[p]
    
    if old_proxies:
        logger.info(f"🗑️ Удалено {len(old_proxies)} прокси старше {max_age_days} дней")
    
    return len(old_proxies)

# ============================================================
# ПАРСИНГ ПРОКСИ
# ============================================================

async def fetch_proxies_from_url(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Парсит прокси из одного источника"""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 200:
                text = await response.text()
                proxies = []
                for line in text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('//') and not line.startswith('*'):
                        if ':' in line and len(line) > 3:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                ip_part = parts[0].strip()
                                if re.match(r'^[\d\.]+$', ip_part) or '.' in ip_part:
                                    proxies.append(line)
                logger.info(f"✅ {url[:60]}... -> {len(proxies)} прокси")
                return proxies
            else:
                logger.warning(f"⚠️ {url[:60]}... -> статус {response.status}")
                return []
    except Exception as e:
        logger.error(f"❌ Ошибка парсинга {url[:60]}...: {e}")
        return []


async def parse_all_proxies() -> Set[str]:
    """Парсит прокси из всех источников (возвращает множество)"""
    logger.info(f"\n🌐 Скачиваю прокси из {len(CONFIG['sources'])} источников...")
    
    all_proxies = set()
    successful_sources = 0
    
    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_proxies_from_url(session, url) for url in CONFIG['sources']]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"❌ Ошибка в источнике {i+1}: {result}")
                continue
            if result:
                successful_sources += 1
                for proxy in result:
                    all_proxies.add(proxy)
    
    logger.info(f"\n📊 Успешно обработано: {successful_sources}/{len(CONFIG['sources'])} источников")
    logger.info(f"📊 Всего собрано уникальных прокси: {len(all_proxies)}")
    
    return all_proxies

# ============================================================
# ПРОВЕРКА ПРОКСИ (ПИНГ, БЕЗ TELEGRAM)
# ============================================================

async def ping_proxy(session: aiohttp.ClientSession, proxy: str) -> Dict:
    """Проверяет прокси через простой HTTP-запрос (пинг)"""
    start_time = time.time()
    result = {
        'proxy': proxy,
        'status': False,
        'time': 0,
        'error': None,
    }
    
    try:
        proxy_url = proxy
        if not proxy_url.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            proxy_url = f'http://{proxy_url}'
        
        async with session.get(
            CONFIG["test_url"],
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])
        ) as response:
            if response.status == 200:
                result['status'] = True
                result['time'] = round(time.time() - start_time, 2)
            else:
                result['error'] = f"HTTP {response.status}"
    
    except asyncio.TimeoutError:
        result['error'] = "Timeout"
    except aiohttp.ClientProxyConnectionError:
        result['error'] = "Proxy connection error"
    except aiohttp.ClientConnectorError:
        result['error'] = "Connector error"
    except aiohttp.ClientHttpProxyError as e:
        result['error'] = f"HTTP proxy error: {e}"
    except Exception as e:
        result['error'] = str(e)[:50]
    
    result['time'] = round(time.time() - start_time, 2)
    return result


async def ping_all_proxies(proxies: Set[str]) -> List[str]:
    """Проверяет все прокси через простой пинг (возвращает список рабочих)"""
    if not proxies:
        logger.warning("❌ Нет прокси для проверки!")
        return []
    
    proxies_list = list(proxies)
    total = len(proxies_list)
    good = []
    checked = 0
    
    logger.info(f"\n🏓 Пингую {total} прокси...\n")
    
    connector = aiohttp.TCPConnector(limit=CONFIG["max_concurrent"], ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [ping_proxy(session, proxy) for proxy in proxies_list]
        
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            checked += 1
            
            if result['status']:
                good.append(result['proxy'])
                status_icon = "✅"
                extra = f"пинг {result['time']}s"
            else:
                status_icon = "❌"
                extra = f"ошибка: {result['error']}"
            
            progress = int((checked / total) * 40)
            bar = "█" * progress + "░" * (40 - progress)
            print(f"\r[{bar}] {checked}/{total} | {status_icon} {result['proxy'][:35]}... {extra}", end="")
    
    print(f"\n\n{'='*60}")
    print(f"✅ Проверка завершена!")
    print(f"📊 Всего: {total}")
    print(f"🟢 Рабочих: {len(good)}")
    print(f"🔴 Не рабочих: {total - len(good)}")
    print(f"{'='*60}\n")
    
    return good

# ============================================================
# ОСНОВНАЯ ФУНКЦИЯ С ЦИКЛОМ (КАЖДУЮ МИНУТУ)
# ============================================================

async def main_loop():
    """Основной цикл проверки прокси (каждую минуту)"""
    iteration = 0
    
    print(f"\n{'='*60}")
    print("  🔍 ПРОКСИ-ПАРСЕР + ЧЕКЕР v5.3 (без Telegram)")
    print(f"  Интервал: {CONFIG['check_interval']} сек (каждую минуту)")
    print(f"  Удаление прокси старше: {CONFIG['max_proxy_age_days']} дней")
    print(f"  Источников: {len(CONFIG['sources'])}")
    print(f"{'='*60}\n")
    
    while True:
        iteration += 1
        start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"  🔄 ИТЕРАЦИЯ #{iteration} | {start_time.strftime('%d.%m.%Y %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        try:
            # 1. Загружаем существующие прокси с датами
            existing_proxies = load_proxies_with_dates(CONFIG["good_proxies_file"])
            
            # 2. Удаляем прокси старше 2 дней
            removed = remove_old_proxies(existing_proxies, CONFIG["max_proxy_age_days"])
            if removed > 0:
                save_proxies_with_dates(existing_proxies, CONFIG["good_proxies_file"])
            
            # 3. Парсим новые прокси
            new_proxies = await parse_all_proxies()
            
            # 4. Фильтруем только те, которых ещё нет
            existing_set = set(existing_proxies.keys())
            to_check = new_proxies - existing_set
            
            if not to_check:
                logger.info("ℹ️ Новых прокси не найдено")
            else:
                logger.info(f"🆕 Найдено {len(to_check)} новых прокси")
                
                # 5. Проверяем новые прокси (пинг)
                working = await ping_all_proxies(to_check)
                
                # 6. Добавляем работающие в существующий список
                now = datetime.now()
                for proxy in working:
                    existing_proxies[proxy] = now
                    logger.info(f"➕ Добавлен новый прокси: {proxy}")
                
                # 7. Сохраняем обновлённый список
                if working:
                    save_proxies_with_dates(existing_proxies, CONFIG["good_proxies_file"])
                    print(f"\n✅ Добавлено {len(working)} новых рабочих прокси")
                else:
                    logger.info("ℹ️ Новые прокси не прошли проверку")
            
            # 8. Показываем статистику
            print(f"\n📊 Текущая статистика:")
            print(f"  • Всего прокси в базе: {len(existing_proxies)}")
            print(f"  • Из них старше {CONFIG['max_proxy_age_days']} дней: {removed}")
            
            # 9. Ждём 1 минуту до следующей проверки
            elapsed = (datetime.now() - start_time).total_seconds()
            wait_time = max(0, CONFIG["check_interval"] - elapsed)
            print(f"\n⏳ Следующая проверка через {wait_time:.0f} сек...")
            await asyncio.sleep(wait_time)
            
        except KeyboardInterrupt:
            logger.info("\n⏹️ Проверка остановлена пользователем")
            break
        except Exception as e:
            logger.error(f"❌ Критическая ошибка в цикле: {e}")
            import traceback
            traceback.print_exc()
            await asyncio.sleep(CONFIG["check_interval"])


async def main():
    """Главная функция"""
    try:
        await main_loop()
    except KeyboardInterrupt:
        print("\n\n⏹️ Проверка остановлена пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️ Проверка остановлена пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()