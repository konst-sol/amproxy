#!/usr/bin/env python3

import sys, os, time
# для сети
import socket
import socks
import pycurl
pycurl.global_init(pycurl.GLOBAL_ALL)
import threading
import subprocess
# для логирования
import traceback
import logging, logging.handlers
from logging import debug, info, error
import queue

# <НАСТРОЙКИ>
HTTP_PROXY_PORT = 8888 # порт этой программы
START_PORT = 9000 # стартовый порт для клиентских ciadpi
TEST_PORT = 9999 # порт для поиска стратегии
STRATEGIES_FILE = 'params.txt'
#STRATEGIES_FILE = 'strats.txt'
STRATEGIES = [] # список тестируемых стратегий
RULES_FILE = 'rules.txt'
DIRECT_FILE = 'direct.txt'
FAILED_FILE = 'failed.txt'
TEST_TIMEOUT = 2 # таймаут для проверки доступности и поиска стратегии (секунды)
TEST_CONNECTTIMEOUT = 2 # таймаут на установку соединения
CHECK_TIMEOUT = 60 # таймаут для всего времени проверки (секунды)
CIADPI_EXE = 'ciadpi.exe' if sys.platform == 'win32' else './ciadpi'
LOG_LEVEL = logging.DEBUG # logging.INFO/logging.ERROR для обычного использования
LOG_FILE = sys.argv[0].split('.')[0]+'.log'
# </НАСТРОЙКИ>

# <ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ>
# сохраненные правила для доменов
RULES = {} # {domen: strategy|"DIRECT"}
RULES_TEST_TIME = {} # {domen: test_time}
FAILED = [] # [(domen, test_time), ...] домены для которых не найдена стратегия
# Служебные данные процессов
param_to_port = {} # {params: port}
active_processes = {} # {port: subprocess.Popen}
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


def load_rules():
    global RULES, RULES_TEST_TIME
    debug('загрузка правил')
    if os.path.exists(RULES_FILE):
        try:
            with (open(RULES_FILE, 'r', encoding='utf-8') as f,
                  open(DIRECT_FILE, 'r', encoding='utf-8') as d):
                for s in f:
                    domen, test_time, params = s.split(maxsplit=2)
                    RULES[domen] = params.strip()
                    RULES_TEST_TIME[domen] = int(test_time)
                for s in d:
                    domen, test_time = s.split(maxsplit=1)
                    RULES[domen] = 'DIRECT'
                    RULES_TEST_TIME[domen] = int(test_time)
        except Exception as err:
            debug(f'[Ex] {err}')
        info(f'[*] Загружено {len(RULES)} правил')
    if os.path.exists(FAILED_FILE):
        try:
            with open(FAILED_FILE, 'r', encoding='utf-8') as f:
                for s in f:
                    domen, test_time = s.split()
                    FAILED.append((domen, int(test_time)))
        except Exception as err:
            debug(f'[Ex] {err}')
        info(f'[*] Загружено {len(RULES)} правил')

def save_rules():
    debug('сохранение правил')
    with (open(RULES_FILE, 'w', encoding='utf-8') as f,
          open(DIRECT_FILE, 'w', encoding='utf-8') as d):
        for domen in RULES:
            if RULES[domen] == 'DIRECT':
                print(f'{domen} {RULES_TEST_TIME[domen]}', file=d)
            else:
                print(f'{domen} {RULES_TEST_TIME[domen]} {RULES[domen]}', file=f)
    with open(FAILED_FILE, 'w', encoding='utf-8') as f:
        for domen, test_time in FAILED:
            print(f'{domen} {test_time}', file=f)

def is_port_in_use(port, host='127.0.0.1'): 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # connect_ex возвращает 0, если подключение успешно (порт занят)
        return s.connect_ex((host, port)) == 0

def search_free_port(port, host='127.0.0.1'):
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # connect_ex возвращает 0, если подключение успешно (порт занят)
            if s.connect_ex((host, port)) != 0:
                return port
        port += 1


def test_url(url, proxy_port=None):
    # Проверяет, скачивается ли страница целиком.
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    # -s (Silent mode)
    c.setopt(c.NOPROGRESS, 1)
    # -L (Follow redirects)
    c.setopt(c.FOLLOWLOCATION, 1)
    # скачиваем в /dev/null
    c.setopt(c.WRITEFUNCTION, lambda x: None)

    if proxy_port:
        c.setopt(c.PROXY, f"socks5h://127.0.0.1:{proxy_port}")
    else:
        c.setopt(c.PROXY, "") # Прямое соединение

    # Тайм-ауты
    c.setopt(c.CONNECTTIMEOUT, TEST_CONNECTTIMEOUT) # Время установки коннекта
    c.setopt(c.TIMEOUT, TEST_TIMEOUT)  # время сквчивания всей страницы
    # Ограничиваем максимальный размер (нам не нужно качать гигабайты)
    # 100 КБ обычно НЕ достаточно, чтобы понять, работает ли стратегия
    #c.setopt(c.MAXFILESIZE, 102400)

    try:
        # Чтобы проверить именно chunked, заставляем curl дождаться конца передачи
        c.perform()
        # Если дошли сюда - значит данные получены полностью
        return True
    except pycurl.error as err:
        # проверяем код возврата и сообщение об ошибке
        code, msg = err.args
        if code == 35:
            # ошибка SSL/TLS
            if 'unsupported protocol' in msg:
                # unsupported protocol - соединение установлено, но сервер
                # не поддерживае современные протоколы. считаем успехом
                return True
            # alert decode error, alert handshake failure - стратегия
            # портит данные
            return False
        if code in [0, 60]:
            # 60 - соединение установлено, но сервер использует устаревший
            # сертификат безопасности. считаем успехом
            return True
        # elif code == 18:
        #     return False # Стратегия портит чанки
        # elif code in [7, 28, 52, 56]:
        #     return False # Полная блокировка
        return False
    finally:
        c.close()


def run_tester(target_domain):
    # проверка доступности и подбор параметров, если напрямую не вышло
    # возвращает стратегию или 'DIRECT'
    url = f'https://{target_domain}'

    # Проверяем доступен ли ресурс напрямую
    info(f'[*] Проверка {target_domain} напрямую...')
    if test_url(url):
        info(f'[+] {target_domain} доступен НАПРЯМУЮ.')
        return 'DIRECT'

    # Подбор стратегии через ciadpi
    info(f'[*] Прямой доступ закрыт. Подбор стратегии для {target_domain}...')
    # сначала проверяем стратегии из RULES
    strats = [s for s in RULES.values() if s != 'DIRECT']
    # добавляем из STRATEGIES
    strats += STRATEGIES

    start_time=time.time()
    tested_params = [] # уже протестированные стратегии
    for params in strats:
        if params in tested_params:
            # не повторяемся
            continue
        tested_params.append(params)
        if time.time()-start_time > CHECK_TIMEOUT:
            debug(f'Подбор стратегии > {CHECK_TIMEOUT} сек. Прерывание')
            return None
        if is_port_in_use(TEST_PORT):
            error('ПОРТ ДЛЯ ПРОВЕРКИ ЗАКРЫТ')
            return None
        debug(f'Проверяется стратегия для {target_domain}: {params}')
        cmd = [CIADPI_EXE, '-p', str(TEST_PORT)] + params.split()
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        time.sleep(0.5) # полсекунды на открытие порта
        for i in range(3):
            if test_url(url, TEST_PORT):
                info(f'[!] Найдена стратегия для {target_domain}: {params}')
                p.terminate(); p.wait()
                return params
        p.terminate(); p.wait()
    return None


def ensure_ciadpi(port, params):
    # проверяет запущен ли ciadpi, и если нет - запускаем
    debug(f'старт: port: {port}, params: {params}')
    if port in active_processes and active_processes[port].poll() is None:
        debug('ciadpi уже запущен')
        return True
    cmd = [CIADPI_EXE, '-i', '127.0.0.1', '-p', str(port)] + params.split()
    try:
        debug(f'запускаем ciadpi: {" ".join(cmd)}')
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL
                                )
        active_processes[port] = proc
        time.sleep(0.5) # полсекунды на открытие порта
        return True
    except Exception as err:
        debug(f'[Ex] {err}')
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
        # shutdown(SHUT_RD) гарантирует, что recv() во ВТОРОМ потоке 
        # мгновенно получит пустой байт и завершит цикл.
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception as err:
            debug(f'[Ex] {err}')
            pass


def handle_client(client_socket):
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

        # выбор DIRECT или ByeDPI
        params = RULES.get(host)
        if params is None:
            params = run_tester(host) # подбираем стратегию
            if params:
                RULES[host] = params
                RULES_TEST_TIME[host] = int(time.time())
                #save_rules()
            else:
                info('[-] стратегия не найдена!')
                params = 'DIRECT'
                FAILED.append((host, int(time.time())))
        else:
            info(f'[!] Используем готовую стратегию для {host}: {params}')


        # Подключение к серверу
        info(f"Connecting to {host}:{port} [{'HTTPS' if is_https else 'HTTP'}]")
        remote_socket = socks.socksocket()
        remote_socket.settimeout(60)

        if params == 'DIRECT':
            pass
        else:
            # определяем порт ciadpi
            global START_PORT
            target_port = param_to_port.get(params)
            if not target_port:
                # ciadpi еще не запущен
                # while True:
                #     # ищем неоткрытый порт
                #     if is_port_in_use(START_PORT):
                #         START_PORT += 1
                #     else:
                #         break
                target_port = param_to_port[params] = START_PORT
                START_PORT += 1
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
        th = threading.Thread(target=pipe, args=(client_socket, remote_socket), name="Pipe-C2R")
        th.daemon = True
        th.start()
        # Основной поток обрабатывает обратное направление
        pipe(remote_socket, client_socket)

    except Exception as err:
        error(f"Error handling client: {err}")
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
    debug(f'{sys.argv[0]} старт {time.strftime("%d.%m.%Y %H:%M")}')
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
            # Называем потоки для удобства отладки
            t = threading.Thread(target=handle_client, args=(client_sock,),
                                 name="ClientHandler")
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
