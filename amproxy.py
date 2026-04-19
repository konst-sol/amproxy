#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "curl-cffi",
#   "pysocks",
#   "beautifulsoup4",
# ]
# ///

import sys, os, time
from datetime import timedelta
from pathlib import Path
from fnmatch import fnmatch
# для сети
import socket
import socks
import asyncio
from curl_cffi import requests, CurlError
from curl_cffi.requests.exceptions import RequestException
import threading
import subprocess
# 16k
from bs4 import BeautifulSoup
# from bs4 import XMLParsedAsHTMLWarning
# import warnings
# # Отключаем предупреждение BeautifulSoup
# # "you're using an HTML parser to parse an XML document"
# warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from urllib.parse import urljoin, urlparse
# для логирования
import logging, logging.handlers
from logging import debug, info, error
import queue
import signal
# аргументы ком. строки
from argparse import ArgumentParser
# конфиг-файл
from configparser import ConfigParser

# <НАСТРОЙКИ>
# дефолтные
HOST = '127.0.0.1'
PORT = 8888 # порт этой программы
STRATEGIES_FILE = 'params.txt'
CIADPI_EXE = 'ciadpi.exe' if sys.platform == 'win32' else './ciadpi'
IMPERSONATE = 'chrome120' # каким браузером прикидываемся
# каталог для кэша
CACHE_DIR = 'cache'
# Файлы для кэширования информации о проверках по одному домену на строке
# в скобках - формат строки
RULES_FILE = 'rules.txt' # стратегии (домен<пробел>время_проведения_теста<пробел>стратегия)
USER_RULES_FILE = 'user-rules.txt' # пользовательские стратегии (домен<пробел>стратегия)
DIRECT_FILE = 'direct.txt' # домены доступные напрямую (домен<пробел>время_проведения_теста)
FAILED_FILE = 'failed.txt' # домены для которых стратегия не найдена (домен<пробел>время_проведения_теста)
HISTORY_FILE = 'history.txt' # стратегии применявшиеся ранее (домен<пробел>стратегия_1|стратегия_2|...)
URLS_FILE = 'urls.txt' # список urls, найденных при парсинге страницы
BACKUP_FILES = 0 # 0/1 сохранять ли резервные копии файлов кэша (debug)
# Конфигурационный файл
CONFIG_FILE = 'amproxy.ini'
# Черный список доменов
BLACKLIST_FILE = 'blacklist.txt'
DIRECT_TEST_TIMEOUT = 4. # таймаут для проверки доступности (секунды)
PROXY_TEST_TIMEOUT = 5. # таймаут для поиска стратегии
SCAN_PAGE_TIMEOUT = 20. # общее время обработки страницы при поиске стратегии
CURL_THREAD_LIMIT = 10 # сколько потоков использовать для проверки стратегий
NUMBER_OF_TESTS = 2 # количество проверок прямой доступности и каждой стратегии
# время устаревания разных статусов в часах:
DIRECT_TTL = 7*24 # прямое подключение
PROXY_TTL = 7*24 # подключение через ciadpi
FAILED_TTL = 8 # прямое подключение если стратегия для ciadpi не найдена
LOG_LEVEL = 'INFO' # ERROR/INFO/DEBUG
LOG_FILE = 'amproxy.log'
# </НАСТРОЙКИ>

# <CLI>
args_parser = ArgumentParser() #description='Описание скрипта'
args_parser.add_argument('-s', '--section', help='раздел в конфиг-файле')
args_parser.add_argument('-c', '--config', help='конфиг-файл')
# дополнительный необязательный аргумент
group = args_parser.add_mutually_exclusive_group()
group.add_argument('domain', nargs='?', help='домен для тестирования')

command_line_args = args_parser.parse_args()
config_section = None
if command_line_args.section:
    config_section = command_line_args.section
    print(f'[C] Используется раздел конфиг-файла: {config_section}')
if command_line_args.config:
    if Path(command_line_args.config).exists():
        CONFIG_FILE = command_line_args.config
        print(f'[C] Используется конфиг-файл: {CONFIG_FILE}')
    else:
        print(f'[C] Конфиг-файл {command_line_args.config} не найден')

# </CLI>

# <CONFIG_FILE>
def _set_config_value(key, value):
    # устанавливаем глобальные переменные из конфига
    var_name = key.upper()
    # Проверяем существует ли уже такая переменная в глобальном пространстве
    if var_name not in globals():
        print(f'[C] Неизвестная опция в конфиг-файле: {key}')
        return
    current_value = globals()[var_name]
    # Сохраняем тип дефолтной переменной (int, float, str)
    target_type = type(current_value)
    if target_type not in (int, float, str):
        # Переназначаем только переменные int, float и str
        print(f'[C] Неизвестная опция в конфиг-файле: {key}')
        return
    try:
        # Пытаемся привести строку из конфига к типу дефолта
        globals()[var_name] = target_type(value)
        print(f'[C] {var_name}: {value}')
    except ValueError:
        print(f'[C] Не удалось преобразовать {var_name} в {target_type.__name__}')

# Считываем конфиг-файл
config = ConfigParser()
config.read(CONFIG_FILE)
# Считываем из раздела [DEFAULT]
# (По умолчанию имена разделов чувствительны к регистру)
for key, value in config.defaults().items():
    _set_config_value(key, value)
# считываем из раздела, указанного в ком. строке (-s <раздел>)
if config_section:
    if config.has_section(config_section):
        for key, value in config.items(config_section):
            _set_config_value(key, value)
    else:
        print(f'[C] Раздел {config_section} не найден')

# </CONFIG_FILE>

# <ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>
strategies = [] # список тестируемых стратегий
# Служебные данные процессов
params_to_port = {} # {params: port}
active_processes = {} # {port: subprocess.Popen}
# Глобальный реестр доменов
domain_registry = None # объект класса DomainRegistry {domain: DomainInfo}
# Черный список доменов
blacklist = set()
# </ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>

# <DEBUG>
# Настройка вывода
class LevelFormatter(logging.Formatter):
    # Форматы для разных уровней
    formats = {
        logging.INFO: "%(message)s",
        logging.DEBUG: "[D] %(filename)s:%(lineno)d: %(funcName)s: %(message)s",
        logging.ERROR: "[E] %(filename)s:%(lineno)d: %(funcName)s: %(message)s",
    }
    def format(self, record):
        log_fmt = self.formats.get(record.levelno, "%(levelname)s: %(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Безопасное логирование
log_queue = queue.Queue()
def setup_logging():
    handlers = []
    # Превращаем путь в объект Path
    if LOG_FILE:
        log_path = CACHE_DIR / LOG_FILE
        log_path.parent.mkdir(parents=True, exist_ok=True) # если CACHE_DIR ещё нет
        # Вывод в файл
        # размер лог-файла 100 КБ, храним 4 старые копии
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=100 * 1024,
            backupCount=4,
            encoding='utf-8'
        )
        file_handler.setFormatter(LevelFormatter())
        handlers.append(file_handler)
    # Вывод в консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LevelFormatter())
    handlers.append(console_handler)
    # Listener будет забирать логи из очереди и отдавать их в ротатор
    listener = logging.handlers.QueueListener(log_queue, *handlers) # respect_handler_level=True если разный log_level для разных handler
    listener.start()
    # Настраиваем корневой логгер отправлять всё в очередь
    logger = logging.getLogger()
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)
    logger.addHandler(logging.handlers.QueueHandler(log_queue))
    # Вывод exception
    global print_exc
    print_exc = logger.exception
    # отключить вывод asyncio и curl_cffi
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    #logging.getLogger('curl_cffi').setLevel(logging.WARNING)
    return listener

# Вывод статуса ciadpi, статистики использования стратегий
# и добавления доменов в кэш
# по Ctrl+Break / kill -USR1 <PID> (pkill -USR1 -f amproxy.py)
def print_status(signum, frame):
    # Функция-обработчик сигнала для вывода информации
    print_ciadpi_status()
    print_params_stat()
    print_summary()

# Регистрация обработчика
def regsig():
    if sys.platform == 'win32':
        # В Windows SIGUSR1 нет, используем SIGBREAK (Ctrl+Break)
        signal.signal(signal.SIGBREAK, print_status)
    else:
        # В Linux/MacOS используем SIGUSR1 (kill -USR1 PID)
        signal.signal(signal.SIGUSR1, print_status)

def print_ciadpi_status():
    info('\n' + '='*50)
    info(' СТАТУС ЗАРЕГИСТРИРОВАННЫХ ПРОЦЕССОВ ciadpi')
    info('='*50)

    if not active_processes:
        info(' Активных процессов ciadpi нет.')
    else:
        info(f'{'PORT':<8} | {'PID':<8} | {'PARAMS'}')
        info('-' * 50)
        # Собираем данные из словарей params_to_port и active_processes
        # Для удобства создадим обратный маппинг портов в параметры
        port_to_params = {v: k for k, v in params_to_port.items()}
        for port, proc in active_processes.items():
            pid = proc.pid
            params = port_to_params.get(port, 'неизвестно')
            # Проверяем, живой ли процесс на самом деле
            status = 'LIVE' if proc.poll() is None else 'DEAD'
            info(f'{port:<8} | {pid:<8} | {params} [{status}]')
    info('='*50 + '\n')

def print_params_stat():
    info('='*50)
    info('СТАТИСТИКА ИСПОЛЬЗОВАНИЯ СТРАТЕГИЙ')
    info('='*50)
    stat = {}
    for domain in domain_registry:
        dom = domain_registry[domain]
        if dom.params is None: continue
        if dom.params in stat:
            stat[dom.params] += 1
        else:
            stat[dom.params] = 1
    info(f'{'NUM':<3} | {'PARAMS'}')
    info('-' * 50)
    for d, n in sorted(stat.items(), key=lambda item: item[1]):
        info(f'{n:<3} | {d}')
    info('='*50+'\n')

# summary
summary = {
    'DIRECT': [],
    'PROXY':  [],
    'FAILED': [],
    'UPDATE': [],
    }
summary_lock = threading.Lock()
def update_summary(status, domain):
    with summary_lock:
        summary[status].append(domain)
def print_summary():
    info('='*50)
    info('ДОБАВЛЕНЫ ДОМЕНЫ ЗА ЭТОТ СЕАНС')
    info('='*50)
    for s in summary:
        if not summary[s]:
            continue
        if s == 'UPDATE':
            info('Обновлены:')
            info('\n'.join(f'  {i}' for i in summary[s]))
        elif s == 'PROXY':
            info('В категорию PROXY добавлены:')
            for d in summary[s]:
                dom = domain_registry.get(d)
                if dom is not None:
                    info(f'  {d} ({dom.params})')
                else:
                    info(f'  {d} (не зарегистрирован)')
        else:
            info(f'В категорию {s} добавлены:')
            info('\n'.join(f'  {i}' for i in summary[s]))
    info('')

# </DEBUG>

# <DOMAININFO>
class DomainInfo:
    TTL = {
        # время устаревания разных статусов
        'DIRECT': DIRECT_TTL*60*60,
        'PROXY': PROXY_TTL*60*60,
        'FAILED': FAILED_TTL*60*60
    }
    def __init__(self, domain, status=None, params=None,
                 test_time=0, user_config=False, extern_proxy=None):
        self.domain = domain
        self.status = status # PROXY / DIRECT / FAILED / EXTERN
        self.extern_proxy = extern_proxy # url внешнего прокси, f.e. socks5://localhost:1080
        self.test_time = test_time # Время последней проверки (в секундах)
        self.params = params
        self.history_params = []  # Список стратегий, которые работали раньше
        self.user_config = user_config # Стратегия задана пользователем
        self.urls = set()
        self.lock = threading.Lock() # чтобы не запускать несколько run_test одновременно

    def _update(self, status, params=None):
        # Обновляем status, params и test_time
        if self.status is None:
            # новый статус
            update_summary(status, self.domain)
        else:
            update_summary('UPDATE', self.domain)
        self.status = status
        if params:
            # Если это новая стратегия, сохраняем старую в историю
            if self.params and self.params != params:
                if self.params not in self.history_params:
                    self.history_params.append(self.params)
            self.params = params
        if not self.user_config:
            # не обновляем если пользовательская стратегия
            self.test_time = int(time.time())

    def check_expired(self):
        # Возвращает None если требуется проверка
        # в противном случае DIRECT или params
        if not self.status:
            return None
        if self.user_config:
            # не проверяем устаревание
            return self.params
        res = (time.time() - self.test_time) > self.TTL.get(self.status, 3600)
        if not res:
            if self.status in ('DIRECT', 'FAILED'):
                return 'DIRECT'
            return self.params
        return None

    def _check_error(self, e):
        # Проверяем Exception
        # Возвращает True/False
        err_code = getattr(e, 'code', 0)
        err_msg = str(e).lower()

        # 60 (плохой сертификат) - успех
        if err_code == 60:
            # соединение установлено, но сервер использует
            # устаревший сертификат безопасности. считаем успехом
            return True

        # 35 (SSL Connect) - успех ТОЛЬКО если протокол не поддерживается
        if err_code == 35:
            if 'unsupported protocol' in err_msg:
                # unsupported protocol - соединение установлено,
                # но сервер не поддерживает современные протоколы.
                # считаем успехом
                return True
            # если alert decode error, alert handshake failure
            # значит стратегия портит данные
        return False

    def _try_dns(self):
        # Проверка DNS
        # Возвращает ip или None
        try:
            ip = socket.gethostbyname(self.domain)
            # Для честной проверки можно добавить сравнение с DoH через requests
            debug(f'[OK] {self.domain} IP: {ip}')
            return ip
        except socket.gaierror:
            debug(f'[BLOCK] {self.domain} Не удалось разрешить имя. Используйте DoT/DoH')
            return None

    def _try_tcp(self, ip, port):
        # Проверка доступности IP (L3 блокировка)
        # Возвращает True/False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            debug(f'[OK] {self.domain} Порт 443 открыт. IP не заблокирован')
            return True
        debug(f'[BLOCK] {self.domain} Тайм-аут. Вероятная блокировка по IP-адресу')
        return False

    def _try_http(self, url):
        # Проверка прямого доступа по http
        # Возвращает True/False
        try:
            kw = {'impersonate': IMPERSONATE,
                  'timeout': DIRECT_TEST_TIMEOUT,
                  'verify': False}
            response = requests.get(url, **kw)
            return response.status_code is not None
        except (CurlError, RequestException) as err:
            return self._check_error(err)
        except Exception:
            return False

    def _test_strategies(self, url, update=True):
        # Подбор стратегии через ciadpi
        # Возвращает (params, content) или 'DIRECT'
        info(f'[*] Прямой доступ закрыт. Подбор стратегии для {self.domain}')
        # Проверяем историю (предыдущие рабочие параметры)
        # Сначала пробуем последний известный рабочий вариант
        pre_strats = []
        if self.params:
            pre_strats.append(self.params)
        # Добавляем остальные из истории (уникальные)
        for params in self.history_params:
            if params not in pre_strats:
                pre_strats.append(params)
        # Добавляем работающие стратегии
        for dom in domain_registry.values():
            if dom.params and dom.params not in pre_strats:
                pre_strats.append(dom.params)
        debug(f'Предварительная проверка {len(pre_strats)} стратегий')
        # Предварительная проверка
        res = asyncio.run(self._find_working_params(url, pre_strats))
        if res:
            if update: self._update('PROXY', res[0])
            debug(f'найдена стратегия для {self.domain}: {res[0]}')
            return res
        # Если история не помогла — запускаем поиск
        # по всем остальным strategies
        remaining_strats = []
        for params in strategies:
            if params not in pre_strats:
                remaining_strats.append(params)
        debug(f'Проверка остальных {len(remaining_strats)} стратегий')
        res = asyncio.run(self._find_working_params(url, remaining_strats))
        if res:
            if update: self._update('PROXY', res[0])
            debug(f'найдена стратегия для {self.domain}: {res[0]}')
            return res
        # подбор параметров закончился неудачей - соединяем напрямую
        if update: self._update('FAILED')
        return 'DIRECT'

    async def _test_params(self, url, params, semaphore, found_event):
        # Проверка одной стратегии
        # Возвращает (params, content) или None
        async with semaphore:
            if found_event.is_set():
                return None
            port = get_free_port()
            args = params.split()
            proc = None
            try:
                # Запускаем ciadpi (не используем run_ciadpi потому что async)
                proc = await asyncio.create_subprocess_exec(
                    CIADPI_EXE, '-i', '127.0.0.1', '-p', str(port), *args,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await asyncio.sleep(0.4) # Пауза на инициализацию прокси
                if proc.returncode is not None:
                    # proc.poll() отсутствует
                    return None
                proxy_url = f'socks5h://127.0.0.1:{port}'
                proxies = {'http': proxy_url, 'https': proxy_url}
                # Пытаемся проверить конфиг NUMBER_OF_TESTS раз
                for _ in range(NUMBER_OF_TESTS):
                    if found_event.is_set():
                        return None
                    try:
                        async with requests.AsyncSession() as s:
                            response = await s.get(
                                url,
                                proxies=proxies,
                                impersonate=IMPERSONATE,
                                timeout=PROXY_TEST_TIMEOUT,
                            )
                            # Успех. Ставим флаг для всех остальных
                            found_event.set()
                            return (params, response.content)
                    except (CurlError, RequestException) as err:
                        if self._check_error(err):
                            found_event.set()
                            return (params, '')
                    except Exception:
                        # Если попытка не удалась, просто пробуем следующую
                        pass
                    # Короткая пауза между попытками внутри одной стратегии
                    await asyncio.sleep(0.5)
            finally:
                # Корректно завершаем ciadpi в любом случае
                if proc is not None:
                    try:
                        proc.terminate()
                        await proc.wait()
                    except:
                        pass
        return None

    async def _check_blocked(self, url, proxies, semaphore):
        # Скачиваем страницу по ссылке и проверяем на доступность
        # Возвращает url (страница не доступна) или None

        # для подсчета размера скачаного
        downloaded_bytes = 0
        def count_bytes(chunk):
            nonlocal downloaded_bytes
            downloaded_bytes += len(chunk)

        async with semaphore:  # Ждем разрешения на выполнение запроса
            async with requests.AsyncSession() as s:
                try:
                    res = await s.get(
                        url,
                        proxies=proxies,
                        impersonate=IMPERSONATE,
                        content_callback=count_bytes,
                        timeout=PROXY_TEST_TIMEOUT,
                        allow_redirects=False,
                    )
                except CurlError as err:
                    # страница заблокирована
                    # 28 - Operation timed out
                    if err.code == 28 and downloaded_bytes > 0:
                        return url
                except Exception as err:
                    pass
        return None

    async def _scan_page(self, content, target_url, proxies,
                         max_duration=SCAN_PAGE_TIMEOUT):
        # Парсим content, находим ссылки и проверяем их на доступность
        # Возвращает список url
        soup = BeautifulSoup(content, 'html.parser')
        # Собираем картинки, скрипты и стили
        tags_config = {
            #'a': ['href'],
            'img': ['src', 'data-src', 'data-lazy-src'],
            'source': ['src', 'srcset'],
            'script': ['src'],
            'link': ['href']
        }
        urls = []
        for tag_name, attrs in tags_config.items():
            for tag in soup.find_all(tag_name):
                for attr in attrs:
                    val = tag.get(attr)
                    if not val: continue

                    # обработка srcset и обычных ссылок
                    raw_urls = val.split(',')
                    for item in raw_urls:
                        clean_item = item.strip().split(' ')[0] # берем только URL
                        # data:image/gif;base64
                        if (clean_item and
                            not clean_item.startswith(('data:', 'blob:'))):
                            url = urljoin(target_url, clean_item)
                            if url not in urls: urls.append(url)

        if 1: # [!!] с добавлением <a> работает сильно хуже (ограничить кол-во ссылок)
            num = 0
            for a in soup.find_all('a', href=True):
                href = a['href']
                # Формируем полный путь
                # Если href уже абсолютный, urljoin его не изменит
                url = urljoin(target_url, href)
                # Фильтруем только http/https (отсекаем почту, якоря и js)
                if url.startswith(('http://', 'https://')) and url not in urls:
                    urls.append(url)
                    num += 1
                    if num >= 10: #len(urls) >= 30:
                        break

        debug(f'проверка {len(urls)} ресурсов на блокировку...')
        found_results = []
        semaphore = asyncio.Semaphore(CURL_THREAD_LIMIT)
        tasks = [self._check_blocked(url, proxies, semaphore) for url in urls]
        try:
            # лимит на всю проверку
            for coro in asyncio.as_completed(tasks, timeout=max_duration):
                result = await coro
                if result:
                    found_results.append(result)
        except asyncio.TimeoutError:
            debug(f'лимит {max_duration} сек исчерпан. Возвращаем найденное')

        debug(f'найдено {len(found_results)} заблокированных ресурсов')
        return found_results


    async def _find_working_params(self, url, params_list):
        # Возвращает (params, content) или None
        found_event = asyncio.Event()
        tasks = []
        semaphore = asyncio.Semaphore(CURL_THREAD_LIMIT)
        for p in params_list:
            tsk = asyncio.create_task(self._test_params(url, p, semaphore, found_event))
            tasks.append(tsk)
            await asyncio.sleep(0.2) # небольшое преимущество первым стратегиям

        result = None
        try:
            # as_completed вернет первую задачу, которая выполнила return
            for finished_task in asyncio.as_completed(tasks):
                res = await finished_task
                if res:
                    result = res
                    break # Нашли первую рабочую стратегию, выходим
        finally:
            # Отменяем все проверки, которые еще висят в очереди или в процессе
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    # *Основная функция*
    def run_test(self, target_url, related=False):
        # Проверка доступности и подбор параметров, если напрямую не вышло.
        # Возвращает стратегию или 'DIRECT'
        # Если related == True - проверяется ссылка из тестируемой страницы
        debug(f'{self.domain} - {target_url} - {related}')
        if self.user_config:
            info(f'[!] Используем пользовательскую стратегию для {self.domain}: '
                  f'{self.params or self.status}')
            return self.params or self.status
        res = self.check_expired()
        if not related and res is not None:
            info(f'[!] Используем готовую стратегию для {self.domain}: {res}')
            return res
        with self.lock:
            # Double-check: вдруг кто-то уже проверил, пока мы ждали замок
            res = self.check_expired()
            if not related and res is not None:
                info(f'[!] Используем готовую стратегию для {self.domain}: {res}')
                return res

            # Проверяем доступен ли ресурс
            info(f'[*] Проверка {self.domain} напрямую...')
            # Проверяем DNS
            ip = self._try_dns()
            if not ip:
                # Блокировка DNS
                info(f'[X] {self.domain} ошибка при получении DNS')
                self._update('FAILED')
                return 'DIRECT'

            # Проверяем доступность сервера
            parsed_url = urlparse(target_url)
            port = int(parsed_url.port or (80 if parsed_url.scheme == 'http' else 443))
            if not self._try_tcp(ip, port):
                # скорее всего блокировка по ip-адресу
                info(f'[X] {self.domain} ошибка подключения к серверу')
                self._update('FAILED')
                return 'DIRECT'
            # Проверяем http
            for _ in range(NUMBER_OF_TESTS):
                if self._try_http(target_url):
                    info(f'[+] {self.domain} доступен НАПРЯМУЮ.')
                    self._update('DIRECT')
                    return 'DIRECT' # не проверять незаблокированные домены

            # проверка http не пройдена
            ret = self._test_strategies(target_url)
            if ret == 'DIRECT':
                info(f'[X] {self.domain} стратегия не найдена')
                self._update('FAILED')
                return 'DIRECT'

            if related:
                # идет проверка встроенных в страницу ссылок (не создаем рекурсию)
                return ret[0] # не используется

            params, content = ret
            # определяем порт ciadpi
            proxy_port = get_params_to_port(params)
            # запуск ciadpi
            if not ensure_ciadpi(proxy_port, params):
                error('ensure_ciadpi вернул False')
                return ret
            # указываем прокси
            proxy_url = f'socks5h://127.0.0.1:{proxy_port}'
            proxies = {'http': proxy_url, 'https': proxy_url}

            # может быть блокировка 16 KB
            rel_list = asyncio.run(self._scan_page(content, target_url, proxies))
            tested_hosts = []
            threads = []
            for tested_url in rel_list:
                parsed_url = urlparse(tested_url)
                host = parsed_url.hostname
                dom = get_domain_info(host)
                dom.urls.add(tested_url)
                if host in tested_hosts:
                    continue
                if dom is self:
                    # перепроверяем стратегию на ссылках из content
                    debug(f'перепроверка: {tested_url}')
                    ret = self._test_strategies(tested_url, update=False)
                    if ret == 'DIRECT':
                        debug('стратегия для обхода 16к не найдена. '
                              f'для {host} будут недоступны большие файлы')
                        continue
                    else:
                        if ret[0] == params:
                            continue
                        tested_hosts.append(host)
                        params = ret[0]
                        self._update('PROXY', params)
                else:
                    # новый домен найденный в content
                    # один поток для одного домена
                    tested_hosts.append(host)
                    th = threading.Thread(target=dom.run_test, args=(tested_url, True))
                    th.daemon = True
                    th.start()
                    threads.append(th)

            for th in threads:
                th.join()

            return params

# </DOMAININFO>

# <DOMAINREGISTRY>
# dict-подобный класс - список всех доменов
# ключ: доменное имя (строка), значение: объект класса DomainInfo
class DomainRegistry:
    def __init__(self):
        self._auto_data = {}  # Программные (автоматические) домены
        self._user_data = {}  # Пользовательские из user-rules.txt (в т.ч. с *)
        self._wildcard_keys = set() # Быстрый доступ к списку масок

    def __setitem__(self, key, value):
        if value.user_config:
            self._user_data[key] = value
            if '*' in key:
                self._wildcard_keys.add(key)
        else:
            self._auto_data[key] = value

    def __getitem__(self, key):
        # Точное совпадение в пользовательских стратегиях
        if key in self._user_data:
            return self._user_data[key]
        # Поиск по wildcard в пользовательских стратегиях
        for pattern in self._wildcard_keys:
            if pattern.startswith('*.') and pattern[2:] == key:
                return self._user_data[pattern]
            if fnmatch(key, pattern):
                return self._user_data[pattern]

        # Точное совпадение в авто-доменах
        if key in self._auto_data:
            return self._auto_data[key]
        raise KeyError(f'Домен "{key}" не найден')

    def __contains__(self, key):
        # Используем логику getitem, но возвращаем True/False
        try:
            self[key]
            return True
        except KeyError:
            return False

    def get(self, key):
        try:
            return self[key]
        except KeyError:
            return None

    def __len__(self):
        # Считаем уникальные ключи в обоих словарях
        return len(set(self._auto_data) | set(self._user_data))

    def values(self):
        # Сначала значения авто, затем пользовательские (приоритетные)
        # Объединяем так, чтобы не дублировать значения, если ключи совпали
        combined = {**self._auto_data, **self._user_data}
        return combined.values()

    def __iter__(self):
        # Позволяет делать "for key in ..."
        combined_keys = set(self._auto_data) | set(self._user_data)
        return iter(combined_keys)



# Глобальный реестр доменов
domain_registry = DomainRegistry() # {domain: DomainInfo}
registry_lock = threading.Lock()
def get_domain_info(domain):
    # Безопасно извлекает или создает объект DomainInfo
    with registry_lock:
        if domain not in domain_registry:
            domain_registry[domain] = DomainInfo(domain)
        return domain_registry[domain]

def update_user_params():
    # Обновление пользовательских стратегий
    info('[C] обновление пользовательских стратегий')
    with registry_lock:
        # Удаляем все пользовательские стратегии
        domain_registry._user_data = {}
        domain_registry._wildcard_keys = set()
        # Обновляем 
        _load(USER_RULES_FILE, 'USER')

def watch_file():
    # Мониторинг файла пользовательских стратегий
    filename = USER_RULES_FILE
    debug(f'запуск мониторинга файла {filename}')
    last_mtime = 0
    if filename.exists():
        last_mtime = filename.stat().st_mtime
    while True:
        time.sleep(10)
        if not filename.exists():
            continue
        current_mtime = filename.stat().st_mtime
        if current_mtime != last_mtime:
            debug(f'обнаружено изменение в {filename}')
            update_user_params()
            last_mtime = current_mtime

# <DOMAINREGISTRY/>


# <LOAD_RULES/SAVE_RULES>
# Загрузка/сохранение кэша
# Переназначаем имена файлов в объекты Path
CACHE_DIR = Path(CACHE_DIR)
RULES_FILE = CACHE_DIR / RULES_FILE
USER_RULES_FILE = Path(USER_RULES_FILE) # в текущем каталоге
DIRECT_FILE = CACHE_DIR / DIRECT_FILE
FAILED_FILE = CACHE_DIR / FAILED_FILE
HISTORY_FILE = CACHE_DIR / HISTORY_FILE
URLS_FILE = CACHE_DIR / URLS_FILE

def _load(filename, status, rules=False):
    if not filename.exists(): # проверяем существование файла
        return
    with filename.open(encoding='utf-8') as f:
        for s in f:
            s = s.split('#')[0] # убираем комментарии
            s = s.strip()
            if not s: continue
            if rules:
                # RULES_FILE
                domain, test_time, params = s.split(maxsplit=2)
                dom = DomainInfo(domain, status, params, int(test_time))
            elif status == 'USER':
                # USER_RULES_FILE
                domain, params = s.split(maxsplit=1)
                if params in ('DIRECT', 'BLOCK'):
                    dom = DomainInfo(domain, params, user_config=True)
                elif params.startswith('EXTERN'):
                    dom = DomainInfo(domain, 'EXTERN', user_config=True,
                                     extern_proxy=params[7:])
                else:
                    dom = DomainInfo(domain, 'PROXY', params, user_config=True)
            else:
                # DIRECT_FILE и FAILED_FILE
                domain, test_time = s.split(maxsplit=1)
                dom = DomainInfo(domain, status, test_time=int(test_time))
            domain_registry[domain] = dom

def load_rules():
    debug('загрузка правил')
    _load(RULES_FILE, 'PROXY', True)
    _load(DIRECT_FILE, 'DIRECT')
    _load(FAILED_FILE, 'FAILED')
    _load(USER_RULES_FILE, 'USER')
    info(f'[+] Загружены правила для {len(domain_registry)} доменов')
    # загружаем историю параметров
    if not HISTORY_FILE.exists():
        return
    with HISTORY_FILE.open(encoding='utf-8') as f:
        for s in f:
            s = s.strip()
            if not s: continue
            domain, params = s.split(maxsplit=1)
            params = params.split('|')
            dom = domain_registry.get(domain)
            if dom:
                dom.history_params = params
    # загружаем urls
    if not URLS_FILE.exists():
        return
    for url in URLS_FILE.open(encoding='utf-8'):
        url = url.rstrip('\r\n')
        parsed_url = urlparse(url)
        dom = domain_registry.get(parsed_url.hostname)
        if dom:
            dom.urls.add(url)

def save_rules():
    debug('сохранение правил')
    # Создаем CACHE_DIR, если его еще нет
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if BACKUP_FILES:
        for fn in (RULES_FILE, DIRECT_FILE, FAILED_FILE, HISTORY_FILE):
            if fn.exists():
                # Создаем резервную копию
                # .with_suffix добавит/заменит расширение
                bak_file = fn.with_suffix(fn.suffix + '.bak')
                fn.replace(bak_file)
    # Записываем данные
    with (RULES_FILE.open('w', encoding='utf-8') as r,
          DIRECT_FILE.open('w', encoding='utf-8') as d,
          FAILED_FILE.open('w', encoding='utf-8') as f,
          HISTORY_FILE.open('w', encoding='utf-8') as h,
          URLS_FILE.open('w', encoding='utf-8') as u):
        for dom in domain_registry.values():
            if dom.status == 'PROXY':
                if not dom.user_config:
                    # игнорируем пользовательские стратегии
                    print(f'{dom.domain} {dom.test_time} {dom.params}', file=r)
            elif dom.status == 'DIRECT':
                print(f'{dom.domain} {dom.test_time}', file=d)
            elif dom.status == 'FAILED':
                print(f'{dom.domain} {dom.test_time}', file=f)
            if dom.history_params:
                print(f'{dom.domain} {"|".join(dom.history_params)}', file=h)
            for url in dom.urls:
                print(url, file=u)

STRATEGIES_FILE = Path(STRATEGIES_FILE)
def load_strategies():
    global strategies
    if not STRATEGIES_FILE.exists():
        error(f'Не найден файл стратегий: {STRATEGIES_FILE}. Выход')
        sys.exit()
    # загрузка стратегий
    with STRATEGIES_FILE.open() as f:
        for s in f:
            s = s.split('#')[0]
            s = s.strip()
            if s and s not in strategies: strategies.append(s)
    info(f'[+] Загружено {len(strategies)} стратегий')

# </LOAD_RULES/SAVE_RULES>


# EXTERN proxy
def set_proxy_from_url(socket_obj, url):
    parsed_url = urlparse(url)
    # Проверка схемы
    proxy_types = {
        'socks5': socks.SOCKS5, 'socks5h': socks.SOCKS5,
        'socks4': socks.SOCKS4, 'socks4a': socks.SOCKS4,
        'http': socks.HTTP
    }
    if parsed_url.scheme not in proxy_types:
        raise ValueError(f'Unsupported proxy scheme: {parsed_url.scheme}. Use socks5, socks5h, socks4, or http.')
    # Проверка хоста
    if not parsed_url.hostname:
        raise ValueError('Proxy URL must include a hostname')
    # Обработка порта (с дефолтными значениями)
    default_ports = {'socks5': 1080, 'socks5h': 1080,
                     'socks4': 1080, 'http': 8080}
    port = parsed_url.port or default_ports.get(parsed_url.scheme, 1080)
    # Удаленный DNS (rdns)
    # Для socks5h и socks4a ставим True. Для остальных — по желанию (обычно True безопаснее)
    is_rdns = parsed_url.scheme in ('socks5h', 'socks4a')
    try:
        socket_obj.set_proxy(
            proxy_type=proxy_types[parsed_url.scheme],
            addr=parsed_url.hostname,
            port=port,
            rdns=is_rdns,
            username=parsed_url.username,
            password=parsed_url.password
        )
    except Exception as e:
        raise RuntimeError(f'Failed to configure proxy: {e}')


#
params_to_port_lock = threading.Lock()
def get_params_to_port(params):
    # Безопасно извлекает или создает запись в params_to_port
    with registry_lock:
        if params not in params_to_port:
            params_to_port[params] = get_free_port()
        return params_to_port[params]


def get_free_port():
    # Запрашиваем у ОС свободный порт и возвращаем его
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # SO_REUSEADDR позволяет повторно использовать порт сразу после закрытия
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0)) # 0 - подключится к любому свободному порту
        # Возвращает кортеж (хост, порт), например ('127.0.0.1', 54321)
        port = s.getsockname()[1]
        debug(f'port: {port}')
        return port


def run_ciadpi(port, params):
    cmd = f'{CIADPI_EXE} -i 127.0.0.1 -p {port} {params}'
    proc = subprocess.Popen(cmd.split(),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(0.4) # Даем время ciadpi запуститься (открыть порт)
    if proc.poll() is not None:
        # ciadpi завершился
        debug('ciadpi не запустился')
        proc.terminate()
        proc.wait()
        return None
    return proc


ensure_ciadpi_lock = threading.Lock()
def ensure_ciadpi(port, params):
    # проверяем запущен ли ciadpi, и если нет - запускаем
    if port in active_processes and active_processes[port].poll() is None:
        debug('ciadpi уже запущен')
        return True
    with ensure_ciadpi_lock:
        # double-check
        if port in active_processes and active_processes[port].poll() is None:
            debug('ciadpi уже запущен')
            return True
        try:
            debug(f'запускаем ciadpi: -p {port} {params}')
            proc = run_ciadpi(port, params)
            if not proc:
                return False
            active_processes[port] = proc
            return True
        except Exception as err:
            debug(f'[Ex] {err}')
            pass
        return False


# <SERVER>
def pipe(source, destination, dom):
    # Пересылает данные между сокетами до закрытия одного из них
    try:
        while True:
            data = source.recv(8192)
            if not data:
                break
            destination.sendall(data)
    except TimeoutError:
        # ловим таймаут
        if dom.status == 'PROXY':
            debug(f'Timeout: {dom.domain} {dom.params} {len(dom.urls)}')
    except Exception as err:
        pass
    finally:
        # shutdown(SHUT_RD) гарантирует, что recv() во втором потоке 
        # мгновенно получит пустой байт и завершит цикл.
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception as err:
            pass


def handle_client(client_socket):
    # обработка запроса клиента
    remote_socket = None
    try:
        client_socket.settimeout(60)
        request = None
        try: request = client_socket.recv(8192)
        except: pass
        if not request: return

        header_line = request.decode('iso-8859-1').split('\n')[0]
        method = header_line.split(' ')[0]

        if method == 'CONNECT':
            # HTTPS: хост и порт берем из строки запроса
            host_port = header_line.split(' ')[1]
            # добавляем порт (443) если не указан
            host, port = (host_port.split(':') + [443])[:2]
            port = int(port)
            is_https = True
        else:
            # HTTP: ищем заголовок Host
            is_https = False
            host, port = None, 80
            for line in request.decode('iso-8859-1').split('\r\n'):
                if line.lower().startswith('host: '):
                    parts = line.split(':')
                    host = parts[1].strip()
                    if len(parts) > 2:
                        port = int(parts[2].strip())
                    break
            if not host:
                return

        remote_socket = socks.socksocket()
        remote_socket.settimeout(60)

        url = f'{"https" if is_https else "http"}://{host}:{port}/'
        dom = get_domain_info(host)
        if dom.status == 'BLOCK':
            debug(f'{host} [BLOCKED]')
            return
        if dom.status == 'EXTERN':
            params = 'EXTERN'
        else:
            params = dom.run_test(url) # получаем стратегию или DIRECT

        # Подключение к серверу
        info(f'[>] Подключение: {host}:{port} '
             f'[{"HTTPS" if is_https else "HTTP"}] '
             f'[{params if params in ("DIRECT", "EXTERN") else "PROXY"}]')

        if params == 'DIRECT':
            pass
        elif params == 'EXTERN':
            debug(f'{host}: подключение к внешнему прокси: {dom.extern_proxy}')
            set_proxy_from_url(remote_socket, dom.extern_proxy)
        else:
            # определяем порт ciadpi
            target_port = get_params_to_port(params)
            # запуск ciadpi
            if not ensure_ciadpi(target_port, params):
                error('ensure_ciadpi вернул False')
                return
            # указываем прокси
            remote_socket.set_proxy(socks.SOCKS5, '127.0.0.1', target_port)

        # соединение
        try:
            remote_socket.connect((host, port))
        except:
            return

        if is_https:
            # Для CONNECT отвечаем клиенту 200 и ничего не шлем серверу (ждем SSL)
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            # Для HTTP пробрасываем исходный запрос серверу
            remote_socket.sendall(request)

        # Двунаправленная пересылка
        th = threading.Thread(target=pipe, args=(client_socket, remote_socket, dom))
        th.daemon = True
        th.start()
        # Основной поток обрабатывает обратное направление
        pipe(remote_socket, client_socket, dom)

    except Exception as err:
        print_exc(str(err))
    finally:
        # Важно закрыть оба сокета, чтобы освободить дескрипторы
        for s in [client_socket, remote_socket]:
            if not s: continue
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception as err:
                pass

def start_proxy():
    start_time = time.time()
    listener = setup_logging()

    if not Path(CIADPI_EXE).exists():
        error(f'Не найден бинарник ByDPI: {CIADPI_EXE}. Выход')
        return
    # Загрузка стратегий
    load_strategies()
    # Загрузка кэша
    load_rules()

    debug(f'{time.strftime("%d.%m.%Y %H:%M")} (PID: {os.getpid()})')

    # Запуск мониторига пользовательского файла стратегий в фоновом потоке
    thr = threading.Thread(target=watch_file, daemon=True)
    thr.start()

    # Запуск сервера
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    regsig() # регистрация SIGUSR1 / SIGBREAK
    info(f'[*] Прокси готов на порту {PORT}')

    try:
        while True:
            client_sock, _ = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        info('Shutting down...')
    finally:
        server.close()
        for p in active_processes.values():
            p.terminate()
            #p.wait()
        save_rules()
        listener.stop()
        print('Uptime:', timedelta(seconds=int(time.time()-start_time)))

# <SERVER/>

# поиск стратегии для одного домена
# кэш не загружается и не сохраняется
def test16(host):
    start_time = time.time()
    listener = setup_logging()
    # загрузка стратегий
    load_strategies()

    dom = get_domain_info(host)
    try:
        res = dom.run_test(f'https://{host}')
    finally:
        for p in active_processes.values():
            p.terminate()
            p.wait()
    info('\nНайдены стратегии:')
    for domain in domain_registry:
        dom = domain_registry[domain]
        info(f'{domain} {dom.params or dom.status}')

    listener.stop()
    print('\ntime:', timedelta(seconds=int(time.time()-start_time)))

#
if __name__ == '__main__':
    if command_line_args.domain:
        test16(command_line_args.domain)
    else:
        start_proxy()

#
