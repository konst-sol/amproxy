#!/usr/bin/env python3

import sys, os, time
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
HTTP_PROXY_PORT = 8888 # порт этой программы
STRATEGIES_FILE = 'params.txt'
CIADPI_EXE = 'ciadpi.exe' if sys.platform == 'win32' else './ciadpi'
CIADPI_EXE += ' -i 127.0.0.1'
RULES_FILE = 'rules.txt'
DIRECT_FILE = 'direct.txt'
FAILED_FILE = 'failed.txt'
TEST_TIMEOUT = 2 # таймаут для проверки доступности и поиска стратегии (секунды)
TEST_CONNECTTIMEOUT = 2 # таймаут на установку соединения
CHECK_TIMEOUT = 60 # таймаут для всего времени проверки (секунды)
CURL_THREAD_LIMIT = 10 # сколько потоков использовать для проверки стратегий
# время устаревания разных статусов в часах
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

# --- Безопасное логирование ---
log_queue = queue.Queue()

def setup_logging():
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LevelFormatter())
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(LevelFormatter())

    # Listener пишет в stdout и файл в единственном потоке, исключая Deadlocks
    listener = logging.handlers.QueueListener(log_queue, console_handler, file_handler)
    listener.start()

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

    def __init__(self, domain, status=None, test_time=0, params=None):
        self.domain = domain
        self.status = status
        self.test_time = test_time # время последней проверки (в секундах)
        self.params = params
        self.history_params = []  # Список стратегий, которые работали раньше
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
        cmd = f'{CIADPI_EXE} -p {port} {params}'
        try:
            proc = subprocess.Popen(cmd.split(),
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(0.4) # Даем время прокси запуститься
            if proc.poll() is not None:
                debug('ciadpi не запустился')
                return False

            c = _get_curl(target_url, f"socks5h://127.0.0.1:{port}")
            c.perform()
            return True
        except pycurl.error as err:
            return self._success(*err.args)
        finally:
            proc.terminate()
            proc.wait()
            if 'c' in locals(): c.close()

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

    @staticmethod
    def find_working_params(target_url):
        # Проверяет стратегии в несколько потоков и возвращает
        # первую успешную стратегию или None
        debug(f'target_url: {target_url}')
        multi = pycurl.CurlMulti()
        active_reqs = {}  # {curl_handle: {'proc': popen_obj, 'params': str}}
        pending_params = list(enumerate(STRATEGIES))
        final_params = None

        def start_worker(idx, params):
            port = get_free_port()
            # Путь к ciadpi (предполагается в текущей папке)
            cmd = f'{CIADPI_EXE} -p {port} {params}'

            try:
                proc = subprocess.Popen(cmd.split(),
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                time.sleep(0.3) # Пауза, чтобы прокси успел поднять сокет
                if proc.poll() is not None:
                    # ciadpi завершился
                    debug('ciadpi не запустился')
                    return

                c = DomainInfo._get_curl(target_url, f'socks5h://127.0.0.1:{port}')
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
                    res['proc'].terminate()
                    res['proc'].wait(timeout=0.5)
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
        res = (time.time() - self.test_time) > self.TTL.get(self.status, 3600)
        if not res:
            if self.status in ('DIRECT', 'FAILED'):
                return 'DIRECT'
            info(f'[!] Используем готовую стратегию для '
                 f'{self.domain}: {self.params}')
            return self.params
        return None

    def run_test(self):
        # Проверка доступности и подбор параметров, если напрямую не вышло.
        # Возвращает стратегию или 'DIRECT'
        res = self._check_expired()
        if res is not None: return res

        with self.lock:
            # Double-check: вдруг кто-то уже проверил, пока мы ждали замок
            res = self._check_expired()
            if res is not None: return res

            # Проверяем доступен ли ресурс напрямую
            url = f'https://{self.domain}'
            info(f'[*] Проверка {self.domain} напрямую...')
            for i in range(3):
                #if test_url(url):
                if self._try_direct(url):
                    info(f'[+] {self.domain} доступен НАПРЯМУЮ.')
                    self._update('DIRECT')
                    return 'DIRECT'

            # Подбор стратегии через ciadpi
            info(f'[*] Прямой доступ закрыт. Подбор стратегии для {self.domain}...')
            # Проверяем историю (предыдущие рабочие параметры)
            # Сначала пробуем последний известный рабочий вариант
            configs_to_test = []
            if self.params:
                configs_to_test.append(self.params)

            # Добавляем остальные из истории (уникальные)
            for params in self.history_params:
                if params not in configs_to_test:
                    configs_to_test.append(params)

            for params in configs_to_test:
                if self._try_single_strategy(params, target_url):
                    self._update('PROXY', params)
                    return params

            # Если история не помогла — запускаем многопоточный поиск
            # по всем STRATEGIES
            params = self.find_working_params(url)
            if params:
                self._update('PROXY', params)
                return params
            # подбор параметров закончился неудачей - соединяем напрямую
            self._update('FAILED')
            return 'DIRECT'


    # Методы для JSON
    def to_dict(self):
        return {
            'status': self.status,
            'params': self.params,
            'history_params': self.history_params,
            'test_time': self.test_time
        }


registry_lock = threading.Lock()
def get_domain_info(domain):
    # Безопасно извлекает или создает объект DomainInfo
    with registry_lock:
        if domain not in domain_registry:
            domain_registry[domain] = DomainInfo(domain)
        return domain_registry[domain]

# </DOMAININFO>

def load_rules():
    debug('загрузка правил')
    if os.path.exists(RULES_FILE): # FIXME
        try:
            with (open(RULES_FILE, 'r', encoding='utf-8') as f,
                  open(DIRECT_FILE, 'r', encoding='utf-8') as d,
                  open(FAILED_FILE, 'r', encoding='utf-8') as e):
                for s in f:
                    s = s.strip()
                    if not s: continue
                    domain, test_time, params = s.split(maxsplit=2)
                    dom = DomainInfo(domain, 'PROXY', int(test_time), params)
                    domain_registry[domain] = dom
                for s in d:
                    s = s.strip()
                    if not s: continue
                    domain, test_time = s.split(maxsplit=1)
                    dom = DomainInfo(domain, 'DIRECT', int(test_time))
                    domain_registry[domain] = dom
                for s in e:
                    s = s.strip()
                    if not s: continue
                    domain, test_time = s.split(maxsplit=1)
                    dom = DomainInfo(domain, 'FAILED', int(test_time))
                    domain_registry[domain] = dom
        except Exception as err:
            debug(f'[Ex] {err}')
            pass
        info(f'[*] Загружены правила для {len(domain_registry)} доменов')

def save_rules():
    debug('сохранение правил')
    with (open(RULES_FILE, 'w', encoding='utf-8') as f,
          open(DIRECT_FILE, 'w', encoding='utf-8') as d,
          open(FAILED_FILE, 'w', encoding='utf-8') as e,
          open('saved.txt', 'w', encoding='utf-8') as s):
        for dom in domain_registry.values():
            if dom.status == 'DIRECT':
                print(f'{dom.domain} {dom.test_time}', file=d)
            elif dom.status == 'PROXY':
                print(f'{dom.domain} {dom.test_time} {dom.params}', file=f)
            else:
                print(f'{dom.domain} {dom.test_time}', file=e)
            if dom.history_params:
                print(f'{dom.domain} {"|".join(dom.history_params)}', file=s)


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


def ensure_ciadpi(port, params):
    # проверяет запущен ли ciadpi, и если нет - запускаем
    debug(f'старт: port: {port}, params: {params}')
    if port in active_processes and active_processes[port].poll() is None:
        debug('ciadpi уже запущен')
        return True
    cmd = f'{CIADPI_EXE} -p {port} {params}'
    try:
        debug(f'запускаем ciadpi: {cmd}')
        proc = subprocess.Popen(cmd.split(),
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL
                                )
        time.sleep(0.5) # полсекунды на открытие порта
        if proc.poll() is not None:
            # ciadpi завершился
            debug('ciadpi не запустился')
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
        debug(f'[Ex] {err}')
        pass
    finally:
        # shutdown(SHUT_RD) гарантирует, что recv() во втором потоке 
        # мгновенно получит пустой байт и завершит цикл.
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception as err:
            debug(f'[Ex] {err}')
            pass


def handle_client(client_socket):
    # обработка запроса клиента
    remote_socket = None
    try:
        client_socket.settimeout(60)
        request = client_socket.recv(8192)
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
        params = dom.run_test() # получаем стратегию или DIRECT

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
                debug(f'[Ex] {err}')
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
        STRATEGIES = [line.strip() for line in f if line.strip()]
    info(f'[+] Загружено {len(STRATEGIES)} стратегий')

    load_rules()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', HTTP_PROXY_PORT))
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
        for p in active_processes.values(): p.terminate()
        save_rules()
        listener.stop()


#
start_proxy()
pycurl.global_cleanup()
#
