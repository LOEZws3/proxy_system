#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Прокси-парсер + чекер с вечным циклом
Версия: 4.1 (постоянный файл good_proxies.txt)
"""

import sys
import io
import asyncio
import aiohttp
import json
import os
import re
import time
from datetime import datetime
from typing import List, Dict, Optional
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
    "timeout": 15,
    "max_concurrent": 1000,
    "test_url": "http://httpbin.org/ip",
    "test_urls": [
        "http://httpbin.org/ip",
        "http://ip-api.com/json",
        "http://ipinfo.io/ip"
    ],
    "good_proxies_file": "good_proxies.txt",
    "bad_proxies_file": "bad_proxies.txt",
    "proxies_file": "proxies.txt",
    "check_interval": 300,
    "min_proxies": 10,
    "sources": [
        # HTTP/HTTPS прокси
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw-http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw-https.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/http.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/https.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/main/http.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/main/https.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/https.txt",
        "https://proxy-list.download/api/v1/get?type=http",
        "https://proxy-list.download/api/v1/get?type=https",
        
        # SOCKS4 прокси
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/socks4.txt",
        "https://proxy-list.download/api/v1/get?type=socks4",
        
        # SOCKS5 прокси
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/main/proxies/socks5.txt",
        "https://proxy-list.download/api/v1/get?type=socks5",
        
        # Дополнительные источники
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/https.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    ]
}

# ============================================================
# ФУНКЦИИ РАБОТЫ С ФАЙЛАМИ
# ============================================================

def ensure_files():
    """Создаёт файлы, если их нет"""
    files = [CONFIG["proxies_file"], CONFIG["good_proxies_file"], CONFIG["bad_proxies_file"]]
    for f in files:
        if not os.path.exists(f):
            with open(f, 'w', encoding='utf-8') as file:
                pass
            print(f"📄 Создан файл: {f}")


def save_proxies_to_file(proxies: List[str], filename: str):
    """Сохраняет прокси в файл (перезаписывает)"""
    with open(filename, 'w', encoding='utf-8') as f:
        for proxy in proxies:
            f.write(f"{proxy}\n")
    logger.info(f"💾 Сохранено {len(proxies)} прокси в {filename}")


def load_proxies_from_file() -> List[str]:
    """Загружает прокси из локального файла"""
    if not os.path.exists(CONFIG["proxies_file"]):
        return []
    
    with open(CONFIG["proxies_file"], 'r', encoding='utf-8') as f:
        proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return proxies

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


async def parse_all_proxies() -> List[str]:
    """Парсит прокси из всех источников"""
    logger.info(f"\n🌐 Скачиваю прокси из {len(CONFIG['sources'])} источников...")
    
    all_proxies = []
    seen = set()
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
                    if proxy not in seen:
                        seen.add(proxy)
                        all_proxies.append(proxy)
    
    logger.info(f"\n📊 Успешно обработано: {successful_sources}/{len(CONFIG['sources'])} источников")
    logger.info(f"📊 Всего собрано уникальных прокси: {len(all_proxies)}")
    
    return all_proxies

# ============================================================
# ПРОВЕРКА ПРОКСИ
# ============================================================

async def check_proxy(session: aiohttp.ClientSession, proxy: str, test_url: str) -> Dict:
    """Проверяет один прокси"""
    start_time = time.time()
    result = {
        'proxy': proxy,
        'status': False,
        'ip': None,
        'time': 0,
        'error': None,
        'type': 'http'
    }
    
    if proxy.startswith('socks5://') or 'socks5' in proxy:
        proxy_type = 'socks5'
    elif proxy.startswith('socks4://') or 'socks4' in proxy:
        proxy_type = 'socks4'
    else:
        proxy_type = 'http'
    
    result['type'] = proxy_type
    
    try:
        proxy_url = proxy
        if not proxy_url.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            proxy_url = f'http://{proxy_url}'
        
        async with session.get(
            test_url,
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])
        ) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    result['status'] = True
                    result['ip'] = data.get('origin', data.get('ip', 'Unknown'))
                except:
                    text = await response.text()
                    result['status'] = True
                    result['ip'] = text.strip()[:50]
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


async def check_all_proxies(proxies: List[str]) -> Dict:
    """Проверяет все прокси с несколькими тестовыми URL"""
    good = []
    bad = []
    total = len(proxies)
    checked = 0
    
    if not proxies:
        logger.warning("❌ Нет прокси для проверки!")
        return {'good': [], 'bad': [], 'total': 0}
    
    logger.info(f"\n🔍 Начинаю проверку {total} прокси...\n")
    start_time = time.time()
    
    connector = aiohttp.TCPConnector(limit=CONFIG["max_concurrent"], ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for proxy in proxies:
            test_url = CONFIG["test_urls"][checked % len(CONFIG["test_urls"])]
            tasks.append(check_proxy(session, proxy, test_url))
        
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            checked += 1
            
            if result['status']:
                good.append(result)
                status_icon = "✅"
                extra = f"IP: {result['ip']} ({result['time']}s)"
            else:
                bad.append(result)
                status_icon = "❌"
                extra = f"Ошибка: {result['error']}"
            
            progress = int((checked / total) * 40)
            bar = "█" * progress + "░" * (40 - progress)
            print(f"\r[{bar}] {checked}/{total} | {status_icon} {result['proxy'][:35]}... {extra}", end="")
    
    elapsed = round(time.time() - start_time, 2)
    
    print(f"\n\n{'='*60}")
    print(f"✅ Проверка завершена!")
    print(f"📊 Всего: {total}")
    print(f"🟢 Рабочих: {len(good)}")
    print(f"🔴 Не рабочих: {len(bad)}")
    print(f"⏱️ Время: {elapsed} сек")
    print(f"{'='*60}\n")
    
    return {
        'good': good,
        'bad': bad,
        'total': total
    }

# ============================================================
# ОСНОВНАЯ ФУНКЦИЯ С ЦИКЛОМ
# ============================================================

async def main_loop():
    """Основной цикл проверки прокси (бесконечный)"""
    iteration = 0
    
    print(f"\n{'='*60}")
    print("  🔍 ПРОКСИ-ПАРСЕР + ЧЕКЕР v4.1 (ПОСТОЯННЫЙ ФАЙЛ)")
    print(f"  Таймаут: {CONFIG['timeout']} сек")
    print(f"  Интервал: {CONFIG['check_interval']//60} мин")
    print(f"  Файл: {CONFIG['good_proxies_file']}")
    print(f"  Источников: {len(CONFIG['sources'])}")
    print(f"{'='*60}\n")
    
    while True:
        iteration += 1
        start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"  🔄 ИТЕРАЦИЯ #{iteration} | {start_time.strftime('%d.%m.%Y %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        try:
            proxies = await parse_all_proxies()
            
            if not proxies:
                logger.warning("⚠️ Не удалось спарсить прокси из интернета.")
                logger.info("📂 Пробую загрузить из локального файла...")
                proxies = load_proxies_from_file()
                
                if not proxies:
                    logger.error("❌ Нет прокси для проверки!")
                    logger.info(f"⏳ Ждём {CONFIG['check_interval']//60} минут...")
                    await asyncio.sleep(CONFIG["check_interval"])
                    continue
            
            result = await check_all_proxies(proxies)
            
            elapsed = (datetime.now() - start_time).total_seconds()
            
            print(f"\n{'='*60}")
            print(f"📊 ИТОГ ИТЕРАЦИИ #{iteration}:")
            print(f"  • Собрано прокси: {len(proxies)}")
            print(f"  • Рабочих: {len(result['good'])}")
            print(f"  • Не рабочих: {len(result['bad'])}")
            print(f"  • Время: {round(elapsed, 2)} сек")
            print(f"{'='*60}\n")
            
            # ============================================================
            # ✅ СОХРАНЯЕМ В ОДИН ПОСТОЯННЫЙ ФАЙЛ (ПЕРЕЗАПИСЫВАЕМ)
            # ============================================================
            if result['good']:
                good_list = [p['proxy'] for p in result['good']]
                save_proxies_to_file(good_list, CONFIG["good_proxies_file"])
                print(f"\n✅ Найдено {len(good_list)} рабочих прокси")
                print(f"💾 Сохранено в {CONFIG['good_proxies_file']}")
                
                print("\n📋 Примеры рабочих прокси:")
                for p in result['good'][:10]:
                    print(f"  • {p['proxy']}")
            else:
                print("❌ Рабочих прокси не найдено.")
            
            print(f"\n⏳ Следующая проверка через {CONFIG['check_interval']//60} минут...")
            await asyncio.sleep(CONFIG["check_interval"])
            
        except KeyboardInterrupt:
            logger.info("\n⏹️ Проверка остановлена пользователем")
            break
        except Exception as e:
            logger.error(f"❌ Критическая ошибка в цикле: {e}")
            import traceback
            traceback.print_exc()
            logger.info(f"⏳ Ждём {CONFIG['check_interval']//60} минут...")
            await asyncio.sleep(CONFIG["check_interval"])


async def main():
    """Главная функция"""
    ensure_files()
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