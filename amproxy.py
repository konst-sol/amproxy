#!/usr/bin/env python3

import sys, os, time
from pathlib import Path
# для сети
import socket
import socks
import pycurl
pycurl.global_init(pycurl.GLOBAL_ALL)
import threading
import subprocess
from io import BytesIO
# для логирования
import traceback
import logging, logging.handlers
from logging import debug, info, error
import queue

# <НАСТРОЙКИ>
HTTP_PROXY_HOST = '127.0.0.1'
HTTP_PROXY_PORT = 8888 # порт этой программы
STRATEGIES_FILE = 'params.txt'
CIADPI_EXE = 'ciadpi.exe' if sys.platform == 'win32' else './ciadpi'
# Файлы для кэширования информации о проверках по одному домену на строке
# в скобках - формат строки
RULES_FILE = 'rules.txt' # стратегии (домен<пробел>время_проведения_теста<пробел>стратегия)
USER_RULES_FILE = 'user-rules.txt' # пользовательские стратегии (домен<пробел>стратегия)
DIRECT_FILE = 'direct.txt' # домены доступные напрямую (домен<пробел>время_проведения_теста)
FAILED_FILE = 'failed.txt' # домены для которых стратегия не найдена (домен<пробел>время_проведения_теста)
BACKUP_FILES = True # сохранять резервные копии файлов кэша (debug)
# каталог для кэша
CACHE_DIR = 'cache'
TEST_TIMEOUT = 2 # таймаут для проверки доступности и поиска стратегии (секунды)
TEST_CONNECTTIMEOUT = 2 # таймаут на установку соединения
CHECK_TIMEOUT = 60 # таймаут для всего времени проверки (секунды)
CURL_THREAD_LIMIT = 5 # сколько потоков использовать для проверки стратегий
NUMBER_OF_TESTS = 3 # количество проверок прямой доступности и каждой стратегии
# время устаревания разных статусов в часах:
DIRECT_TTL = 7*24 # прямое подключение
PROXY_TTL = 7*24 # подключение через ciadpi
FAILED_TTL = 8 # прямое подключение если стратегия для ciadpi не найдена
LOG_LEVEL = logging.DEBUG # logging.INFO/logging.ERROR для обычного использования
#LOG_LEVEL = logging.INFO
LOG_FILE = sys.argv[0].split('.')[0]+'.log'
# </НАСТРОЙКИ>


# <ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>
STRATEGIES = [] # список тестируемых стратегий
# Служебные данные процессов
param_to_port = {} # {params: port}
active_processes = {} # {port: subprocess.Popen}
# Глобальный реестр доменов
domain_registry = {} # {domain: DomainInfo}
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
def setup_logging(): #log_file_path, log_level=logging.INFO):
    # Превращаем путь в объект Path
    log_path = CACHE_DIR / LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True) # если CACHE_DIR ещё нет
    # Вывод в файл
    # размер лог-файла 100 КБ, храним 5 старых копий
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, 
        maxBytes=100 * 1024, 
        backupCount=5, 
        encoding='utf-8'
    )
    file_handler.setFormatter(LevelFormatter())
    # Вывод в консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LevelFormatter())
    # Listener будет забирать логи из очереди и отдавать их в ротатор
    listener = logging.handlers.QueueListener(
        log_queue,
        console_handler,
        file_handler,
        respect_handler_level=True
    )
    listener.start()
    # Настраиваем корневой логгер отправлять всё в очередь
    logger = logging.getLogger()
    logger.setLevel(LOG_LEVEL)
    logger.addHandler(logging.handlers.QueueHandler(log_queue))

    return listener

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
                 test_time=0, user_config=False):
        self.domain = domain
        self.status = status
        # если test_time число: время последней проверки (в секундах)
        # если строка: стратегия добавлена пользователем и не проверяется на TTL
        self.test_time = test_time
        self.params = params
        self.history_params = []  # Список стратегий, которые работали раньше
        self.user_config = user_config # Стратегия задана пользователем
        self.lock = threading.Lock() # для проведения теста

    def _update(self, status, params=None):
        # обновляем status, params и test_time
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

    @staticmethod
    def _get_curl(url, proxy=None):
        # Настройка curl
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        # Используем setopt(c.WRITEDATA, buffer) потому что
        # с (c.WRITEFUNCTION, lambda x: None) для каждого пришедшего
        # пакета данных (chunk) libcurl вызывает интерпретатор Python,
        # чтобы выполнить lambda
        buffer = BytesIO()
        c.setopt(c.WRITEDATA, buffer)
        # Переход по редиректам, так как многие сайты при проверке
        # доступности могут перенаправлять с http на https
        c.setopt(c.FOLLOWLOCATION, True)
        c.setopt(c.CONNECTTIMEOUT, TEST_CONNECTTIMEOUT)
        c.setopt(c.TIMEOUT, TEST_TIMEOUT)
        # Важная опция при работе в многопоточных средах
        # или при быстром создании/удалении хендлов.
        # Предотвращает падения из-за системных сигналов таймера
        c.setopt(c.NOSIGNAL, 1)
        # Гарантирует, что каждый новый тест идет через
        # "чистое" соединение, а не использует старый открытый сокет
        # от предыдущего набора параметров
        c.setopt(c.FORBID_REUSE, 1)
        if proxy:
            c.setopt(c.PROXY, proxy)

        return c

    @staticmethod
    def _success(errno, errmsg):
        # проверяет код возврата и сообщение об ошибке curl
        if errno == 35:
            # ошибка SSL/TLS
            if 'unsupported protocol' in errmsg:
                # unsupported protocol - соединение установлено,
                # но сервер не поддерживае современные протоколы.
                # считаем успехом
                return True
            # если alert decode error, alert handshake failure
            # значит стратегия портит данные
        if errno == 60:
            # соединение установлено, но сервер использует
            # устаревший сертификат безопасности. считаем успехом
            return True
        return False

    def _try_direct(self, url):
        # Проверка доступности без прокси
        debug(url)
        c = self._get_curl(url)
        try:
            c.perform()
            return True
        except pycurl.error as err:
            return self._success(*err.args)
        finally:
            c.close()

    def _try_single_strategy(self, params, target_url, timeout=15):
        # Проверка одной конкретной стратегии
        port = get_free_port()
        try:
            proc = run_ciadpi(port, params)
            if not proc:
                return False
            c = self._get_curl(target_url, f"socks5h://127.0.0.1:{port}")
            c.perform()
            return True
        except pycurl.error as err:
            return self._success(*err.args)
        finally:
            proc.terminate()
            proc.wait()
            if 'c' in locals(): c.close()

    def find_working_params(self, target_url, strats):
        # Проверяет стратегии в несколько потоков и возвращает
        # первую успешную стратегию или None
        debug(f'target_url: {target_url}')
        multi = pycurl.CurlMulti()
        active_reqs = {}  # {curl_handle: {'proc': popen_obj, 'params': str}}
        pending_params = list(enumerate(strats))
        final_params = None

        def start_worker(idx, params):
            port = get_free_port()
            try:
                proc = run_ciadpi(port, params)
                if not proc:
                    return
                for _ in range(NUMBER_OF_TESTS):
                    # проверяем стратегию несколько раз
                    c = self._get_curl(target_url, f'socks5h://127.0.0.1:{port}')
                    multi.add_handle(c)
                    active_reqs[c] = {'proc': proc, 'params': params}

            except Exception as err:
                debug(f'[Ex] {err}')

        # Первоначальный запуск проверок (в количестве CURL_THREAD_LIMIT штук)
        for _ in range(min(CURL_THREAD_LIMIT, len(pending_params))):
            idx, p = pending_params.pop(0)
            start_worker(idx, p)
            # следующую проверку запускаем через 0.1 сек
            # чтобы более простые стратегии имели небольшое преимущество
            #multi.select(0.1)
            time.sleep(0.1)

        try:
            while active_reqs and not final_params:
                while True:
                    ret, num_handles = multi.perform()
                    if ret != pycurl.E_CALL_MULTI_PERFORM:
                        break

                while True:
                    queued, ok_list, err_list = multi.info_read()

                    # Если запрос прошел успешно
                    for c in ok_list:
                        res = active_reqs.pop(c)
                        final_params = res['params']
                        # curl.close() и proc.terminate() будут вызваны в finally
                        break

                    # Если запрос завершился ошибкой
                    for c, errno, errmsg in err_list:
                        res = active_reqs.pop(c)
                        if DomainInfo._success(errno, errmsg):
                            # не все ошибки это неудача
                            final_params = res['params']
                            break

                        multi.remove_handle(c)
                        res['proc'].terminate()
                        res['proc'].wait()
                        c.close()

                        if not final_params and pending_params:
                            idx, p = pending_params.pop(0)
                            start_worker(idx, p)

                    if final_params or queued == 0:
                        break
                multi.select(0.1)

        finally:
            # Чистим всё при любом исходе
            for c, res in active_reqs.items():
                try:
                    proc = res['proc']
                    if proc.poll() is not None:
                        proc.terminate()
                        proc.wait() #timeout=0.5
                except: pass
                multi.remove_handle(c)
                c.close()
            multi.close()

        debug(f'found: {final_params}')
        return final_params

    def _check_expired(self):
        # возвращает None если требуется проверка
        # в противном случае DIRECT или params
        if not self.status:
            debug('no status')
            return None
        if self.user_config:
            # не проверяем устаревание
            return self.params
        res = (time.time() - self.test_time) > self.TTL.get(self.status, 3600)
        if not res:
            if self.status in ('DIRECT', 'FAILED'):
                return 'DIRECT'
            info(f'[!] Используем готовую стратегию для '
                 f'{self.domain}: {self.params}')
            return self.params
        return None

    def run_test(self, url):
        # Проверка доступности и подбор параметров, если напрямую не вышло.
        # Возвращает стратегию или 'DIRECT'
        res = self._check_expired()
        if res is not None: return res

        with self.lock:
            # Double-check: вдруг кто-то уже проверил, пока мы ждали замок
            res = self._check_expired()
            if res is not None: return res

            # Проверяем доступен ли ресурс напрямую
            info(f'[*] Проверка {self.domain} напрямую...')
            for _ in range(NUMBER_OF_TESTS):
                if self._try_direct(url):
                    info(f'[+] {self.domain} доступен НАПРЯМУЮ.')
                    self._update('DIRECT')
                    return 'DIRECT'

            # Подбор стратегии через ciadpi
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
                if dom.params not in pre_strats:
                    pre_strats.append(dom.params)
            debug(f'Предварительная проверка {len(pre_strats)} стратегий')
            # предварительная проверка
            for params in pre_strats:
                if self._try_single_strategy(params, url):
                    self._update('PROXY', params)
                    return params
            # Если история не помогла — запускаем многопоточный поиск
            # по всем остальным STRATEGIES
            remaining_starts = []
            for params in STRATEGIES:
                if params not in pre_strats:
                    remaining_starts.append(params)
            debug(f'Проверка остальных {len(remaining_starts)} стратегий')
            params = self.find_working_params(url, remaining_starts)
            if params:
                self._update('PROXY', params)
                return params
            # подбор параметров закончился неудачей - соединяем напрямую
            self._update('FAILED')
            return 'DIRECT'


registry_lock = threading.Lock()
def get_domain_info(domain):
    # Безопасно извлекает или создает объект DomainInfo
    with registry_lock:
        if domain not in domain_registry:
            domain_registry[domain] = DomainInfo(domain)
        return domain_registry[domain]

# </DOMAININFO>


# <LOAD_RULES/SAVE_RULES>
# переназначаем имена файлов в объекты Path
CACHE_DIR = Path(CACHE_DIR)
RULES_FILE = CACHE_DIR / RULES_FILE
#USER_RULES_FILE = CACHE_DIR / USER_RULES_FILE # в подкаталоге CACHE_DIR
USER_RULES_FILE = Path(USER_RULES_FILE) # в текущем каталоге
DIRECT_FILE = CACHE_DIR / DIRECT_FILE
FAILED_FILE = CACHE_DIR / FAILED_FILE

def _load(filename, status, rules=False):
    if filename.is_file(): # проверяем существование файла
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
                    if params == 'DIRECT':
                        dom = DomainInfo(domain, 'DIRECT', user_config=True)
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
    #_load(USER_RULES_FILE, 'USER')
    info(f'[*] Загружены правила для {len(domain_registry)} доменов')


def save_rules():
    debug('сохранение правил')
    # Создаем CACHE_DIR, если его еще нет
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if BACKUP_FILES:
        for fn in (RULES_FILE, DIRECT_FILE, FAILED_FILE):
            if fn.exists():
                # Создаем резервную копию
                # .with_suffix добавит/заменит расширение
                bak_file = fn.with_suffix(fn.suffix + '.bak')
                fn.replace(bak_file)
    # Записываем данные
    with (RULES_FILE.open('w', encoding='utf-8') as f,
          DIRECT_FILE.open('w', encoding='utf-8') as d,
          FAILED_FILE.open('w', encoding='utf-8') as e):
        for dom in domain_registry.values():
            if dom.status == 'PROXY':
                if not dom.user_config:
                    # игнорируем пользовательские стратегии
                    print(f'{dom.domain} {dom.test_time} {dom.params}', file=f)
            elif dom.status == 'DIRECT':
                print(f'{dom.domain} {dom.test_time}', file=d)
            else: # FAILED
                print(f'{dom.domain} {dom.test_time}', file=e)

# <LOAD_RULES/SAVE_RULES/>

def get_free_port():
    # запрашиваем свободный порт и возвращаем его
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
    time.sleep(0.4) # Даем время прокси запуститься (открыть порт)
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
    debug(f'старт: port: {port}, params: {params}')
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


def pipe(source, destination):
    # Пересылает данные между сокетами до закрытия одного из них.
    try:
        while True:
            data = source.recv(8192)
            if not data:
                break
            destination.sendall(data)
    except Exception as err:
        #debug(f'[Ex] {err}')
        pass
    finally:
        # shutdown(SHUT_RD) гарантирует, что recv() во втором потоке 
        # мгновенно получит пустой байт и завершит цикл.
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception as err:
            #debug(f'[Ex] {err}')
            pass


def handle_client(client_socket):
    # обработка запроса клиента
    remote_socket = None
    try:
        client_socket.settimeout(60)
        try: request = client_socket.recv(8192)
        except: pass
        if not request:
            return

        header_line = request.decode('iso-8859-1').split('\n')[0]
        method = header_line.split(' ')[0]

        if method == 'CONNECT':
            # HTTPS: хост и порт берем из строки запроса
            host_port = header_line.split(' ')[1]
            # добавляем порт (443) если не указан
            host, port = (host_port.split(':') + [443])[:2]
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

        dom = get_domain_info(host)
        url = f'{"https://" if is_https else "http://"}{host}/'
        params = dom.run_test(url) # получаем стратегию или DIRECT

        # Подключение к серверу
        info(f'[>] Подключение: {host}:{port} '
             f'[{"HTTPS" if is_https else "HTTP"}] '
             f'[{"DIRECT" if params == "DIRECT" else "PROXY"}]')
        remote_socket = socks.socksocket()
        remote_socket.settimeout(60)

        if params == 'DIRECT':
            pass
        else:
            # определяем порт ciadpi
            target_port = param_to_port.get(params)
            if not target_port:
                target_port = param_to_port[params] = get_free_port()
                # ciadpi еще не запущен
            # запуск ciadpi
            if not ensure_ciadpi(target_port, params):
                error('ensure_ciadpi вернул False')
                return
            # указываем прокси
            remote_socket.set_proxy(socks.SOCKS5, '127.0.0.1', target_port)

        # соединение
        remote_socket.connect((host, int(port)))

        if is_https:
            # Для CONNECT отвечаем клиенту 200 и ничего не шлем серверу (ждем SSL)
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            # Для HTTP пробрасываем исходный запрос серверу
            remote_socket.sendall(request)

        # Двунаправленная пересылка
        th = threading.Thread(target=pipe, args=(client_socket, remote_socket))
        th.daemon = True
        th.start()
        # Основной поток обрабатывает обратное направление
        pipe(remote_socket, client_socket)

    except Exception as err:
        error(f"Error handling client: {err}")
        traceback.print_exc()
    finally:
        # Важно закрыть оба сокета, чтобы освободить дескрипторы
        for s in [client_socket, remote_socket]:
            if not s: continue
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception as err:
                #debug(f'[Ex] {err}')
                pass

def start_proxy():
    listener = setup_logging()

    global STRATEGIES
    debug(f'{sys.argv[0]} стартовал {time.strftime("%d.%m.%Y %H:%M")}')
    if not os.path.exists(STRATEGIES_FILE):
        info(f'Не найден файл стратегий: {STRATEGIES_FILE}. Выход')
        return
    with open(STRATEGIES_FILE) as f:
        # добавляем из STRATEGIES_FILE
        for s in f:
            s = s.split('#')[0]
            s = s.strip()
            if s: STRATEGIES.append(s)
    info(f'[+] Загружено {len(STRATEGIES)} стратегий')

    load_rules()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HTTP_PROXY_HOST, HTTP_PROXY_PORT))
    server.listen(128)
    info(f'[*] Прокси готов на порту {HTTP_PROXY_PORT}')

    try:
        while True:
            client_sock, _ = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        info("Shutting down...")
    except Exception as err:
        debug(f'[Ex] {err}')
        pass
    finally:
        server.close()
        for p in active_processes.values():
            p.terminate()
            #p.wait()
        save_rules()
        listener.stop()


#
start_proxy()
pycurl.global_cleanup()
#
