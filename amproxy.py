#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "curl-cffi",
#   "pysocks",
#   "beautifulsoup4",
#   "requests",
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
import requests as requests2 # для watch_network. с requests из curl_cffi не работает
import base64 # для аутентификации
from bs4 import BeautifulSoup # 16k
from urllib.parse import urljoin, urlparse
# для логирования
import logging, logging.handlers
from logging import exception as print_exc
import queue
import atexit
import signal
# аргументы ком. строки
from argparse import ArgumentParser
# конфиг-файл
from configparser import ConfigParser

APP_NAME = 'amproxy'

# <НАСТРОЙКИ>
# дефолтные
HOST = '127.0.0.1'
PORT = 8888 # порт этой программы
#USER_PASS = 'user:12345' # Учетные данные (логин:пароль)
USER_PASS = '' # если пустая строка - не использовать аутентификацию
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
DYNAMIC_CONFIG = 1 # 0/1 Динамическое изменение настроек/стратегий при смене провайдера
# Таймауты
DIRECT_TEST_TIMEOUT = 5. # таймаут для проверки доступности (секунды)
PROXY_TEST_TIMEOUT = 5. # таймаут для поиска стратегии
SCAN_PAGE_TIMEOUT = 20. # общее время обработки страницы при поиске стратегии
CURL_THREAD_LIMIT = 10 # сколько потоков использовать для проверки стратегий
NUMBER_OF_TESTS = 2 # количество проверок прямой доступности и каждой стратегии
# время устаревания разных статусов в часах:
DIRECT_TTL = 7*24 # прямое подключение
PROXY_TTL = 7*24 # подключение через ciadpi
FAILED_TTL = 8 # прямое подключение если стратегия для ciadpi не найдена
LOG_LEVEL = 'INFO' # ERROR/INFO/DEBUG
LOG_FILE = APP_NAME+'.log'

# Определяем список имен параметров для конфиг-файла
# Сразу после настроек и до всего остального
settings_list = []
def get_settings_list():
    for k, v in globals().items():
        # все параметры должны быть большими буквами и иметь тип int, float, str
        if k.isupper() and type(v) in (int, float, str):
            settings_list.append(k)
get_settings_list()

# Закодированный логин:пароль
AUTH_ENCODED = None
# Конфигурационный файл
CONFIG_NAME = APP_NAME+'.ini' # имя. не меняется
CONFIG_PATH = None # путь к пользовательскому конфиг-файлу (объект Path)
SYSTEM_CONFIG_PATH = None # путь к системному конфиг-файлу (объект Path)
# Секция в конфиг-файле (определяется в ком. строке)
CONFIG_SECTION = None
# Домен для тестирования.
# Если в ком. строке указан доп. аргумент (домен или url) - сервер не запускается,
# и вместо этого производится подбор стратегии для указанного домена (без загрузки кэша)
TESTED_DOMAIN = None
# Обновление кэша в режиме тестирования
UPDATE_CACHE = False

# Переназначаем имена файлов в объекты Path
CACHE_DIR = Path(CACHE_DIR)
USER_RULES_FILE = Path(USER_RULES_FILE)
STRATEGIES_FILE = Path(STRATEGIES_FILE)

# </НАСТРОЙКИ>

# <LOGGING>
# Настройка вывода
class LevelFormatter(logging.Formatter):
    # Форматы для разных уровней
    formats = {
        logging.INFO: "%(message)s",
        logging.DEBUG: "[D] %(filename)s:%(lineno)d: %(funcName)s: %(message)s",
        logging.ERROR: "[E] %(filename)s:%(lineno)d: %(funcName)s: %(message)s",
    }

    def __init__(self):
        super().__init__()
        # Создаем тяжелые объекты один раз при инициализации
        self._formatters = {
            level: logging.Formatter(fmt) for level, fmt in self.formats.items()
        }
        self._default_formatter = logging.Formatter(
            "%(levelname)s: %(message)s"
        )

    def format(self, record):
        formatter = self._formatters.get(record.levelno, self._default_formatter)
        return formatter.format(record)

class LogManager:
    def __init__(self):
        # Безопасное логирование через очередь сообщений
        self.log_queue = queue.Queue()
        self.logger = logging.getLogger(__name__)
        self.listener = None
        # Временная настройка вывода в консоль до загрузки конфига
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(LevelFormatter())

        self.listener = logging.handlers.QueueListener(self.log_queue, console_handler)
        self.logger.addHandler(logging.handlers.QueueHandler(self.log_queue))
        self.logger.setLevel(LOG_LEVEL)
        self.listener.start()
        atexit.register(self.stop)
        # функции вывода логов
        global info, debug, error
        info = self.logger.info
        debug = self.logger.debug
        error = self.logger.error

    def upgrade(self):
        # Настройка после чтения конфига
        # Останавливаем старый listener
        if self.listener:
            self.listener.stop()
        handlers = []
        # Настройка вывода в файла
        if LOG_FILE:
            log_path = CACHE_DIR / LOG_FILE
            log_path.parent.mkdir(parents=True, exist_ok=True) # если CACHE_DIR ещё нет
            # Вывод в файл
            # размер лог-файла 100 КБ, храним 4 старые копии
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=100*1024, backupCount=4, encoding='utf-8'
            )
            file_handler.setFormatter(LevelFormatter())
            handlers.append(file_handler)

        # Настройка вывода в консоль
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(LevelFormatter())
        handlers.append(console_handler)

        # Запуск нового listener
        # listener будет забирать логи из очереди и отдавать их в ротатор
        self.listener = logging.handlers.QueueListener(self.log_queue, *handlers)
        self.listener.start()

        # Обновление уровня
        level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
        self.logger.setLevel(level)

    def stop(self):
        # Безопасно останавливает listener, избегая гонки потоков при Ctrl+C.
        # Проверяем, существует ли объект listener и инициализирован ли его поток
        if self.listener and getattr(self.listener, "_thread", None) is not None:
            try:
                self.listener.stop()
            except AttributeError:
                # На случай, если поток исчез прямо во время вызова
                pass

# </LOGGING>

# <CLI>
def parse_cli_args():
    global CONFIG_PATH, CONFIG_SECTION, TESTED_DOMAIN, UPDATE_CACHE
    args_parser = ArgumentParser() #description='Описание скрипта'
    args_parser.add_argument('-c', '--config', help='конфиг-файл')
    args_parser.add_argument('-s', '--section', help='раздел в конфиг-файле')
    args_parser.add_argument('-u', '--update', action='store_true',
                             help='обновлять кэш (в режиме поиска стратегий)')
    # дополнительный необязательный аргумент (проверяемый домен)
    group = args_parser.add_mutually_exclusive_group()
    group.add_argument('domain', nargs='?', help='домен или url для поиска стратегий')

    command_line_args = args_parser.parse_args()
    if command_line_args.config:
        CONFIG_PATH = Path(command_line_args.config)
        if CONFIG_PATH.is_file():
            info(f'[C] Используется конфиг-файл: {CONFIG_PATH}')
        else:
            error(f'Не найден конфиг-файл: {CONFIG_PATH}. Выход')
            sys.exit(1)
    if command_line_args.section:
        CONFIG_SECTION = command_line_args.section
        info(f'[C] Используется раздел конфиг-файла: {CONFIG_SECTION}')
    if command_line_args.domain:
        TESTED_DOMAIN = command_line_args.domain
    if command_line_args.update:
        UPDATE_CACHE = True

# </CLI>

# <CONFIG_FILE>
def find_config_file():
    # Поиск конфиг-файла в стандартных местах
    global CONFIG_PATH, SYSTEM_CONFIG_PATH
    # системный конфиг
    if sys.platform == "win32":
        SYSTEM_CONFIG_PATH = (Path(os.environ.get('ProgramData', 'C:\\ProgramData'))
                              / APP_NAME / CONFIG_NAME)
    else:
        SYSTEM_CONFIG_PATH = Path('/etc/') / APP_NAME / CONFIG_NAME

    # Аргумент командной строки
    if CONFIG_PATH:
        # установлен через аргумент cli
        return
    # Переменная окружения
    env_path = os.getenv(APP_NAME+'_CONFIG')
    if env_path and Path(env_path).is_file():
        CONFIG_PATH = Path(env_path)
        return
    # Список мест для последовательного поиска
    search_order = [
        # Текущий рабочий каталог
        Path.cwd() / CONFIG_NAME,
        # Каталог, где лежит сам скрипт
        Path(sys.argv[0]).parent / CONFIG_NAME,
    ]
    # в домашнем каталоге
    if sys.platform == 'win32':
        # без точки
        home_dir = APP_NAME
    else:
        # с точкой
        home_dir = '.'+APP_NAME
    search_order.append(Path.home() / home_dir / CONFIG_NAME)
    # Возвращаем первый существующий файл
    for path in search_order:
        if path.is_file():
            CONFIG_PATH = path
            return
    # Если ничего не нашли, устанавливаем дефолтный путь для создания нового файла
    CONFIG_PATH = Path.home() / home_dir / CONFIG_NAME


def _set_config_value(key, value):
    # устанавливаем глобальные переменные из конфига
    var_name = key.upper()
    # Проверяем существует ли уже такая переменная в глобальном пространстве
    if var_name not in settings_list:
        error(f'Неизвестная опция в конфиг-файле: {key}')
        return
    current_value = globals()[var_name]
    # Сохраняем тип дефолтной переменной (int, float, str, Path)
    target_type = type(current_value)
    try:
        # Пытаемся привести строку из конфига к типу дефолта
        globals()[var_name] = target_type(value)
        if var_name == 'USER_PASS':
            info(f'[C] {var_name}: [hidden]')
        else:
            info(f'[C] {var_name}: {value}')
    except ValueError:
        error(f'Не удалось преобразовать {var_name} в {target_type.__name__}')

# Считываем конфиг-файл
def read_config_file():
    find_config_file()
    if not CONFIG_PATH.exists():
        info(f'Конфиг не найден. Создаем дефолтный; {CONFIG_PATH}')
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CONFIG_PATH.open('w', encoding='utf-8') as f:
            f.write('[DEFAULT]\n\n')
    config = ConfigParser()
    config.read((SYSTEM_CONFIG_PATH, CONFIG_PATH), encoding='utf-8')

    # Считываем из раздела [DEFAULT]
    # (По умолчанию имена разделов чувствительны к регистру)
    for key, value in config.defaults().items():
        _set_config_value(key, value)
    # считываем из раздела, указанного в ком. строке (-s <раздел>)
    if CONFIG_SECTION:
        if config.has_section(CONFIG_SECTION):
            for key, value in config.items(CONFIG_SECTION):
                _set_config_value(key, value)
        else:
            error(f'Раздел {CONFIG_SECTION} не найден')

def add_new_section(isp_name):
    # Дописывает новую секцию в конец конфиг-файла (для watch_network)
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        if f'\n[{isp_name}]' in f.read():
            return
    debug(f'Новый провайдер. Добавляем секцию [{isp_name}] в конфиг-файл')
    with open(CONFIG_PATH, 'a', encoding='utf-8') as f:
        f.write(f'# Секция добавлена автоматически\n[{isp_name}]\n\n')

# </CONFIG_FILE>

# <ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>
strategies = [] # список тестируемых стратегий
# Служебные данные процессов
params_to_port = {} # {params: port}
active_processes = {} # {port: subprocess.Popen}
# Логирование
log_manager = None # объект класса LogManager
# Глобальный реестр доменов
domain_registry = None # объект класса DomainRegistry {domain: DomainInfo}
# </ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>


# <DEBUG>
# Вывод статуса ciadpi, статистики использования стратегий и добавления доменов в кэш
# по Ctrl+Break для Windows
# или kill -USR1 <PID> (pkill -USR1 -f amproxy.py) для *nix
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
        info(f"{'PORT':<8} | {'PID':<8} | {'PARAMS'}")
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
    info(f"{'NUM':<3} | {'PARAMS'}")
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
    info(f'\n{uptime()}\n')

start_time = time.time()
def uptime(txt='Uptime'):
    return f'{txt}: {timedelta(seconds=int(time.time()-start_time))}'

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
                    except Exception:
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
                # прерываемся, поскольку идет проверка встроенных в страницу ссылок
                # (не создаем рекурсию)
                return ret[0] # не используется

            # Перепроверка найденной стратегии
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
                dom = domain_registry.get_domain_info(host)
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
        self._isp_name = None
        self._lock = threading.Lock()
        self._set_cache_path()

    def _set_cache_path(self):
        cache_path = CACHE_DIR
        if self._isp_name:
            # кэш в подкаталоге с именем провайдера
            cache_path = CACHE_DIR / self._isp_name
        debug(f'каталог кэша: {cache_path}')
        self.rules_file = cache_path / RULES_FILE
        self.direct_file = cache_path / DIRECT_FILE
        self.failed_file = cache_path / FAILED_FILE
        self.history_file = cache_path / HISTORY_FILE
        self.urls_file = cache_path / URLS_FILE

    #
    # Методы dict
    #
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

    #
    # Загрузка/сохранение кэша
    #
    def _load(self, filename, status, rules=False):
        if not filename.exists():
            return
        with filename.open(encoding='utf-8') as f:
            lineno = 0
            for s in f:
                lineno += 1
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
                        if not params.startswith('-'):
                            error(f'ошибка в файле {USER_RULES_FILE}: '
                                  f'строка {lineno}: не параметры: {params}')
                        else:
                            dom = DomainInfo(domain, 'PROXY', params,
                                             user_config=True)
                else:
                    # DIRECT_FILE и FAILED_FILE
                    domain, test_time = s.split(maxsplit=1)
                    dom = DomainInfo(domain, status, test_time=int(test_time))
                self[domain] = dom

    def load_rules(self):
        debug('загрузка правил')
        with self._lock:
            self._load(self.rules_file, 'PROXY', True)
            self._load(self.direct_file, 'DIRECT')
            self._load(self.failed_file, 'FAILED')
            self._load(USER_RULES_FILE, 'USER')
            info(f'[+] Загружены правила для {len(self)} доменов')
            # загружаем историю параметров
            if self.history_file.exists():
                with self.history_file.open(encoding='utf-8') as f:
                    for s in f:
                        s = s.strip()
                        if not s: continue
                        domain, params = s.split(maxsplit=1)
                        params = params.split('|')
                        dom = self.get(domain)
                        if dom:
                            dom.history_params = params
            # загружаем urls
            if self.urls_file.exists():
                with self.urls_file.open(encoding='utf-8') as f:
                    for url in f:
                        url = url.rstrip('\r\n')
                        parsed_url = urlparse(url)
                        dom = self.get(parsed_url.hostname)
                        if dom:
                            dom.urls.add(url)

    def save_rules(self):
        debug('сохранение правил')
        # Создаем CACHE_DIR, если его еще нет
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        if BACKUP_FILES:
            for fn in (self.rules_file, self.direct_file,
                       self.failed_file, self.history_file):
                if fn.exists():
                    # Создаем резервную копию
                    # .with_suffix добавит/заменит расширение
                    bak_file = fn.with_suffix(fn.suffix + '.bak')
                    fn.replace(bak_file)
        # Записываем данные
        with (self.rules_file.open('w', encoding='utf-8') as r,
              self.direct_file.open('w', encoding='utf-8') as d,
              self.failed_file.open('w', encoding='utf-8') as f,
              self.history_file.open('w', encoding='utf-8') as h,
              self.urls_file.open('w', encoding='utf-8') as u):
            for dom in self.values():
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

    def update_user_rules(self):
        # Обновление пользовательских стратегий
        info('[C] обновление пользовательских стратегий')
        with self._lock:
            # Удаляем все пользовательские стратегии
            self._user_data = {}
            self._wildcard_keys = set()
            # Обновляем 
            self._load(USER_RULES_FILE, 'USER')

    #
    # Остальные методы
    #
    def get_domain_info(self, domain):
        # Безопасно извлекает или создает объект DomainInfo
        with self._lock:
            if domain not in self:
                self[domain] = DomainInfo(domain)
            return self[domain]

    def set_isp(self, isp_name):
        # Изменение кэша при смене провайдера
        if isp_name == self._isp_name:
            return
        debug(f'новый ISP: {isp_name}. Перезагрузка кэша')
        # Обновление настроек
        # считываем настройки из раздела ISP
        config = ConfigParser()
        config.read(CONFIG_PATH, encoding='utf-8')
        for key, value in config.items(isp_name):
            _set_config_value(key, value)
        # Обновление логирования
        log_manager.upgrade()
        # Обновление кэша
        # сохраняем
        if self._auto_data:
            self.save_rules()
        # обнуляем
        self._auto_data = {}
        self._user_data = {}
        self._wildcard_keys = set()
        # новые пути к файлам кэша
        self._isp_name = isp_name
        self._set_cache_path()
        # обновляем
        self.load_rules()

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
            domain_registry.update_user_rules()
            last_mtime = current_mtime

# <DOMAINREGISTRY/>

def load_strategies():
    # загрузка стратегий
    with STRATEGIES_FILE.open() as f:
        for s in f:
            s = s.split('#')[0]
            s = s.strip()
            if s and s not in strategies: strategies.append(s)
    info(f'[+] Загружено {len(strategies)} стратегий')


def watch_network():
    debug('запуск мониторинга сети')
    last_ip = None
    last_isp = None
    while True:
        # Определяем IP (раз в 60-90 сек)
        current_ip = None
        try:
            current_ip = requests2.get('https://api.ipify.org', timeout=30
                                       ).text.strip()
        except Exception as err:
            debug(f'ip: {err}')
            # не делаем continue чтобы time.sleep()
        # Проверяем смену IP
        if current_ip and current_ip != last_ip:
            debug(f'Обнаружен новый IP: {current_ip}')
            # Определяем провайдера
            # Сервис ip-api.com имеет ограничение:
            # не более 45 запросов в минуту на бесплатном тарифе.
            # Если превысить этот лимит, ваш IP временно забанят.
            try:
                resp_url = f'http://ip-api.com/json/{current_ip}?fields=isp'
                response = requests2.get(resp_url, timeout=30).json()
                current_isp = response.get('isp')
            except Exception as err:
                debug(f'isp: {err}')
            else:
                # Если провайдер сменился
                if current_isp and current_isp != last_isp:
                    if last_isp:
                        info(f'[!] Смена провайдера: {last_isp} -> {current_isp}')
                    else:
                        info(f'[!] Провайдер: {current_isp}')
                    add_new_section(current_isp) # добавляем раздел в конфиг-файл
                    last_isp = current_isp

                    domain_registry.set_isp(current_isp) # обновляем настройки

                last_ip = current_ip

        time.sleep(60) # Интервал проверки


# EXTERN proxy
def set_proxy_from_url(socket_obj, url):
    # конфигурируем socket_obj для работы через прокси
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


params_to_port_lock = threading.Lock()
def get_params_to_port(params):
    # Безопасно извлекает или создает запись в params_to_port
    with params_to_port_lock:
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
    # запускаем ciadpi и проверяем запустился ли
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
    except Exception:
        pass
    finally:
        # shutdown(SHUT_RD) гарантирует, что recv() во втором потоке 
        # мгновенно получит пустой байт и завершит цикл.
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_socket, address):
    # обработка запроса клиента
    remote_socket = None
    try:
        client_socket.settimeout(60)
        request = None
        try: request = client_socket.recv(8192)
        except Exception: pass
        if not request: return

        request = request.decode('utf-8', errors='ignore')
        lines = request.splitlines()
        first_line = lines[0].split()
        if len(first_line) < 3:
            return
        method, path, protocol = first_line

        # Определяем, является ли адрес локальным
        is_local = (address[0] == '127.0.0.1' or address[0] == '::1')
        if AUTH_ENCODED and not is_local:
            # Если аутентификация настроена и клиент НЕ локальный
            # Проверка авторизации
            auth_header = None
            for line in lines:
                if line.lower().startswith('proxy-authorization: basic '):
                    auth_header = line.split()[2]
                    break
            if auth_header != AUTH_ENCODED:
                # Если пароль неверный, возвращаем 407
                response = (
                    'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    'Proxy-Authenticate: Basic realm="Proxy Server"\r\n'
                    'Content-Length: 0\r\n'
                    'Connection: close\r\n\r\n'
                )
                client_socket.sendall(response.encode())
                client_socket.close()
                return

        # Парсим целевой хост и порт
        if method == 'CONNECT':
            # HTTPS: хост и порт берем из строки запроса
            is_https = True
            # добавляем порт (443) если не указан
            host, port = (path.split(':') + [443])[:2]
            port = int(port)
        else:
            # HTTP: ищем заголовок Host
            is_https = False
            host, port = None, 80
            for line in lines:
                if line.lower().startswith('host:'):
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
        dom = domain_registry.get_domain_info(host)
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
        except Exception:
            return

        if is_https:
            # Для CONNECT отвечаем клиенту 200 и ничего не шлем серверу (ждем SSL)
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            # Для HTTP пробрасываем исходный запрос серверу
            # Исправляем запрос
            filtered_lines = []
            # если URL абсолютный (с http://), делаем его относительным
            if path.startswith('http://'):
                parsed_url = urlparse(path)
                out_path = parsed_url.path if parsed_url.path else '/'
                if parsed_url.query:
                    out_path += '?' + parsed_url.query
                filtered_lines.append(f'{method} {out_path} {protocol}')

            # вырезаем Proxy-Auth заголовок
            for line in lines[1:]:
                # Пропускаем (удаляем) заголовки, относящиеся к прокси
                if line.lower().startswith('proxy-'):
                    continue
                filtered_lines.append(line)
            # формируем исправленный запрос
            out_req = '\r\n'.join(filtered_lines) + '\r\n'
            remote_socket.sendall(out_req.encode('utf-8'))

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


def init_app():
    read_config_file()
    # Обновляем логирование
    # Если в конфиг-файле указан другой уровень логирования или путь к логу
    log_manager.upgrade()

    # Проверка необходимых файлов
    if not Path(CIADPI_EXE).exists():
        error(f'Не найден бинарник ByDPI: {CIADPI_EXE}. Выход')
        sys.exit(1)
    if not STRATEGIES_FILE.exists():
        error(f'Не найден файл стратегий: {STRATEGIES_FILE}. Выход')
        sys.exit(1)

    # Глобальный реестр доменов
    global domain_registry
    domain_registry = DomainRegistry() # {domain: DomainInfo}

    load_strategies()


def start_proxy():
    init_app()
    # Загрузка кэша
    domain_registry.load_rules()

    debug(f'{time.strftime("%d.%m.%Y %H:%M")} (PID: {os.getpid()})')

    # Аутентификация
    if USER_PASS:
        global AUTH_ENCODED
        # Закодированный логин:пароль
        AUTH_ENCODED = base64.b64encode(USER_PASS.encode()).decode()
        debug('используется аутентификация')
    # Запуск мониторинга сети. Смена настроек при изменении провайдера
    if DYNAMIC_CONFIG:
        thr = threading.Thread(target=watch_network, daemon=True)
        thr.start()
    # Запуск мониторинга пользовательского файла стратегий
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
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock,addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        # Используем root-логгер или прямой print, так как потоки могут закрываться
        print('Shutting down...')
        sys.exit(0)
    finally:
        server.close()
        for p in active_processes.values():
            p.terminate()
            #p.wait()
        domain_registry.save_rules()
        print(uptime())

# </SERVER>

# поиск стратегии для одного домена
# кэш не загружается
def test_domain(url):
    init_app()

    if not url.startswith(('http://', 'https://')):
        url = 'https://'+url
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    dom = domain_registry.get_domain_info(domain)
    try:
        dom.run_test(url)
    finally:
        for p in active_processes.values():
            p.terminate()
            p.wait()
    info('\nНайдены стратегии:')
    for domain in domain_registry:
        dom = domain_registry[domain]
        info(f'{domain} {dom.params or dom.status}')
    info('')

    if UPDATE_CACHE:
        # если в ком. строке указана опция -u
        debug('update cache')
        saved_domain_registry = DomainRegistry()

        if DYNAMIC_CONFIG:
            # определяем провайдера
            current_ip = requests2.get('https://api.ipify.org', timeout=30).text.strip()
            resp_url = f'http://ip-api.com/json/{current_ip}?fields=isp'
            response = requests2.get(resp_url, timeout=30).json()
            current_isp = response.get('isp')
            debug(f'isp: {current_isp}')
            # переопределяем каталог кэша
            saved_domain_registry._isp_name = current_isp
            saved_domain_registry._set_cache_path()
        # загружаем кэш
        saved_domain_registry.load_rules()
        # переопределяем тестируемый домен
        for domain in domain_registry:
            dom = domain_registry[domain]
            saved_dom = saved_domain_registry.get_domain_info(domain)
            saved_dom._update(dom.status, dom.params)
        # сохраняем кэш
        saved_domain_registry.save_rules()

    print(uptime('time'))

#
if __name__ == '__main__':
    # Настраиваем логирование в самом начале,
    # чтобы дальше можно было использовать info(), debug(), error()
    log_manager = LogManager()
    parse_cli_args()
    if TESTED_DOMAIN:
        # если в ком. строке указан домен
        test_domain(TESTED_DOMAIN)
    else:
        start_proxy()

#
