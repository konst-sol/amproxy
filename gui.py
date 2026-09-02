#!/usr/bin/env python3
# -*- mode: python; coding: utf-8; -*-
# /// script
# requires-python = ">=3.10"
# dependencies = [
# ]
# ///

import sys
import os
import requests
import time
from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
import json
import configparser
import tempfile
import subprocess
import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox

APP_DIR = Path(sys.argv[0]).parent
GUI_CONFIG = APP_DIR / 'gui.ini'

AMPROXY_PATH = APP_DIR / 'amproxy.py'
AMPROXY_CONFIG = APP_DIR / 'amproxy.ini'

HISTORY_FILE = APP_DIR / 'history.txt'


PSIPHON_DIR = APP_DIR / 'psiphon'
# Автоматический выбор URL и имени файла в зависимости от ОС
if sys.platform == 'win32':
    PSIPHON_URL = "https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/windows/psiphon-tunnel-core-i686.exe"
    PSIPHON_EXE = "psiphon-tunnel-core-i686.exe"
elif sys.platform == 'linux':
    PSIPHON_URL = 'https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/linux/psiphon-tunnel-core-x86_64'
    PSIPHON_EXE = "psiphon-tunnel-core-x86_64"
else:
    sys.exit('Неподдерживаемая OS')

PSIPHON_PATH = PSIPHON_DIR / PSIPHON_EXE
PSIPHON_CONFIG = PSIPHON_DIR / 'psiphon.config'
PSIPHON_ETAG_FILE = PSIPHON_DIR / f"{PSIPHON_EXE}.etag"



class ConfigParser(configparser.ConfigParser):
    def __init__(self):
        super().__init__(
            interpolation=None, # чтобы использовать плейсхолдеры
            inline_comment_prefixes=('#', ';'), # комментарий в конце строки
            )

def get_free_port() -> int:
    '''Запрашивает у операционной системы свободный локальный порт.'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def send_command(command, host, port):
    '''Отправляет текстовую команду на управляющий порт прокси-сервера.'''
    try:
        # Создаем TCP-сокет
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Подключаемся к прокси
            sock.connect((host, port))
            # Отправляем команду (добавляем перевод строки для надежности)
            sock.sendall(f'{command}\n'.encode('utf-8'))
            # Ждем ответ от сервера
            buffer = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break # Клиент закрыл соединение
                buffer += chunk
            # Декодируем в текст
            response = buffer.decode('utf-8')
            return response
    except socket.timeout:
        return f'Превышено время ожидания ответа от {host}:{port}'
    except ConnectionRefusedError:
        return f'Не удалось подключиться к {host}:{port}. Прокси-сервер запущен?'
    except Exception as err:
        return f'Произошла непредвиденная ошибка: {err}'


class Entry(ttk.Entry):
    def replace(self, string):
        self.delete(0, 'end')
        self.insert(0, string)

class HistoryEntry(Entry):
    def __init__(self, master=None, on_execute=None, get_commands=None, **kwargs):
        super().__init__(master, **kwargs)
        self.on_execute = on_execute
        self.get_commands = get_commands
        self.history = []
        self.history_index = -1
        self.current_draft = ''
        self.commands = []
        # Привязка событий
        self.bind('<Return>', self._on_enter)
        self.bind('<Up>', self._history_up)
        self.bind('<Down>', self._history_down)
        self.bind('<Tab>', self._autocomplete)

    def _on_enter(self, event):
        command = self.get().strip()
        if command:
            # Сохраняем в историю, если команда уникальна
            if not self.history or self.history[-1] != command:
                self.history.append(command)
            # Вызываем внешнюю функцию обработчика, если она передана
            if self.on_execute:
                self.on_execute(command)
        # Сброс состояния
        self.history_index = -1
        self.current_draft = ''
        self.delete(0, 'end')

    def _history_up(self, event):
        if not self.history:
            return 'break'
        if self.history_index == -1:
            self.current_draft = self.get()
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self._show_history_item()
        return 'break'

    def _history_down(self, event):
        if self.history_index == -1:
            return 'break'
        self.history_index -= 1
        if self.history_index >= 0:
            self._show_history_item()
        else:
            self.replace(self.current_draft)
            self.history_index = -1
        return 'break'

    def _show_history_item(self):
        target_command = self.history[-1 - self.history_index]
        self.replace(target_command)

    def _autocomplete(self, event):
        if not self.get_commands:
            return 'break'
        if not self.commands:
            self.commands = self.get_commands()
        draft = self.get()
        cmd = [c for c in self.commands if c.startswith(draft)]
        if len(cmd) == 1:
            self.replace(cmd[0]+' ')
        elif len(cmd) > 1:
            if self.on_execute:
                self.on_execute(cmd, True)
        return 'break'

    def save_history(self):
        if not self.history:
            return
        with HISTORY_FILE.open('w') as file:
            file.write('\n'.join(self.history)+'\n')

    def load_history(self):
        if not HISTORY_FILE.exists():
            return
        with HISTORY_FILE.open() as file:
            self.history = file.read().splitlines()


class Server(ABC):
    @abstractmethod
    def __init__(self, app, name):
        self.app = app
        self.name = name
        # Ссылка на запущенный процесс
        self.process = None
        # Поток для чтения логов
        self.log_thread = None
        # Временный конфиг для передачи серверу
        self.config = None
        # GUI
        log_tab = ttk.Frame(app.notebook)
        app.notebook.add(log_tab, text=f' {name} Log ')
        self.log_text = tk.Text(log_tab, wrap='char', state='disabled',
                                bg='#1e1e1e', fg='#ffffff')
        self.log_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(log_tab, command=self.log_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.log_text.config(yscrollcommand=scrollbar.set)
        self.log_text.bind('<End>', self._end)
        self.log_text.bind('<BackSpace>', self._end)
        # кол-во строк в log_text
        self.max_lines = 1000

        # Настраиваем цвета под типы уведомлений
        tags = {
            'Info'   : '#81c784',   # Зеленый для базовой инфо
            'Warning': '#ffb74d',   # Оранжевый для предупреждений
            'Error'  : '#e57373',   # Красный для ошибок
            'Raw'    : '#ffffff',   # Белый для нераспознанного текста
        }
        for tag_name, color in tags.items():
            self.log_text.tag_config(tag_name, foreground=color)


    def _end(self, event):
        # прокрутить в самый низ
        self.log_text.yview('end')
        return 'break'

    def _safe_append_log(self, text):
        text, notice_type = self.parse_log(text)
        self.log_text.config(state='normal')
        # Проверяем, виден ли сейчас самый конец текста (индекс "end").
        # Метод bbox() возвращает координаты символа на экране. 
        # Если символ скрыт за пределами видимости, bbox() вернет None.
        # Смещение "-1c" означает "минус один символ", чтобы проверять
        # реальный текст, а не пустую строку после него.
        is_at_bottom = self.log_text.bbox('end-1c') is not None

        self.log_text.insert('end', text, notice_type)

        # Получаем номер последней строки (формат возврата: "строка.символ")
        last_index = self.log_text.index('end-1c')
        current_lines = int(last_index.split('.')[0])
        # Если строк больше лимита, удаляем лишние сверху
        if current_lines > self.max_lines:
            lines_to_delete = current_lines - self.max_lines
            # Удаляем от самого начала (1.0) до начала строки,
            # которая станет новой первой
            self.log_text.delete('1.0', f'{lines_to_delete + 1}.0')

        # Прокручиваем вниз только если пользователь уже был внизу
        if is_at_bottom:
            self.log_text.see('end')
        self.log_text.config(state='disabled')

    def parse_log(self, line):
        return line, 'Raw'

    def log_message(self, text):
        self.app.after(0, self._safe_append_log, text)

    @abstractmethod
    def start(self, cmd):
        try:
            # Запускаем процесс. Перенаправляем stdout и stderr в PIPE
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Сливаем ошибки и обычный вывод в один поток
                text=True, # Читаем как текст, а не байты
                bufsize=1, # Построчный буфер для моментального вывода логов
            )
            self.log_message(
                f'--- Процесс сервера запущен (PID: {self.process.pid}) ---')

            # Создаем фоновый поток, который будет непрерывно читать stdout процесса
            self.log_thread = threading.Thread(target=self.read_output_loop,
                                               daemon=True)
            self.log_thread.start()

        except Exception as e:
            messagebox.showerror('Ошибка запуска', str(e))

    def stop(self):
        if self.config and self.config.exists():
            # удаляем временный конфиг
            self.config.unlink()

        if self.process:
            self.log_message('--- Останавливаем сервер... ---')
            # Завершаем процесс
            self.process.terminate() 
            # Ждем 4 секунды, если не умер — убиваем принудительно
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def read_output_loop(self):
        '''Функция выполняется в отдельном потоке и читает строки из процесса'''
        # Метод readline() блокирует поток, пока сервер не выдаст строку текста
        while self.process and self.process.poll() is None:
            line = self.process.stdout.readline()
            if line:
                self.log_message(line)
        # Если процесс завершился сам или его убили
        if self.process:
            remaining_output = self.process.stdout.read()
            if remaining_output:
                self.log_message(remaining_output)

        self.log_message('--- Процесс сервера завершен ---')
        self.process = None


class AMProxy(Server):
    def __init__(self, app):
        super().__init__(app, 'AMProxy')

    def start(self):
        # указываем в конфиге порт psiphon
        ## data = self.app.text_area.get(1.0, 'end')
        config = ConfigParser()
        config.read(AMPROXY_CONFIG)
        ## config.read_string(data)
        section = config.defaults()
        section['host'] = self.app.amproxy_host.get()
        section['port'] = self.app.amproxy_port.get()
        section['failed_rule'] = 'EXTERN'
        section['default_extern_proxy'] = f'socks5://localhost:{self.app.psiphon_socks5_port.get()}'
        if app.control_port.get():
            section['control_port'] = app.control_port.get()

        # Создаем временный конфиг-файл
        # delete=False гарантирует, что файл не закроется намертво для других программ
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', prefix='amproxy', suffix=AMPROXY_CONFIG.suffix, delete=False)
        self.config = Path(temp_file.name)
        # Записываем измененный конфиг во временный файл
        config.write(temp_file)

        # Использование sys.executable гарантирует запуск на том же
        # интерпретаторе Python (например, .venv/bin/python)
        super().start([sys.executable, AMPROXY_PATH, '-d', '.', '-c', self.config])


class Psiphon(Server):
    regions = ['ANY',
               'AT', 'AU', 'BE', 'BR', 'CA', 'CH', 'CZ', 'DE', 'DK', 'ES',
               'FR', 'GB', 'ID', 'IE', 'IN', 'IT', 'JP', 'KR', 'LT', 'MY',
               'NL', 'NO', 'PL', 'RO', 'RS', 'SE', 'SG', 'US']
    def __init__(self, app):
        super().__init__(app, 'Psiphon')
        # Добавляем тэги
        # Настраиваем цвета под типы уведомлений Psiphon (noticeType)
        tags = {
            'Tunnels'         : '#ba68c8', # Фиолетовый
            'ConnectingServer': '#edfb6e', # Желтый (в процессе)
            'ConnectedServer' : '#39FF14', # Неоновый зеленый (подключено)
            'ConnectedServerRegion': '#39FF14',
            'TotalBytesTransferred': '#00d2ff', # cyan
        }
        for tag_name, color in tags.items():
            self.log_text.tag_config(tag_name, foreground=color)

    def start(self):
        with open(PSIPHON_CONFIG) as file:
            data = json.load(file)
        if self.app.random_port.get():
            self.http_port = get_free_port()
            self.socks_port = get_free_port()
        else:
            self.http_port = int(self.app.psiphon_http_port.get())
            self.socks_port = int(self.app.psiphon_socks5_port.get())
        data['LocalHttpProxyPort'] = self.http_port
        data['LocalSocksProxyPort'] = self.socks_port
        region = self.app.psiphon_regions.get()
        if region != 'ANY':
            data['EgressRegion'] = region
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', prefix='psiphon', suffix=PSIPHON_CONFIG.suffix, delete=False)
        self.config = Path(temp_file.name)
        json.dump(data, temp_file)

        cmd = [PSIPHON_PATH,
               #'-formatNotices',
               '-dataRootDirectory', PSIPHON_DIR,
               '-config', self.config]
        if self.app.psiphon_host.get() == '0.0.0.0':
            cmd += ['-listenInterface', 'any']
        self.log_message(f'Старт Psiphon:\n'
                         f'http: {self.http_port}\n'
                         f'socks5: {self.socks_port}\n'
                         f'path: {PSIPHON_PATH}\n'
                         f'config: {self.config}\n'
                         f'cmd: {" ".join(str(i) for i in cmd)}\n\n')
        super().start(cmd)

    def parse_log(self, line):
        'Парсит JSON-строку от Psiphon и выводит цветной лог'
        try:
            # 1. Десериализуем JSON-строку
            log_data = json.loads(line.strip())
            # 2. Извлекаем основные поля
            timestamp = log_data.get('timestamp', '')
            notice_type = log_data.get('noticeType', 'Info')
            data_field = log_data.get('data', {})
            if timestamp:
                # Время обычно приходит длинным (ISO), сделаем его компактнее (ЧЧ:ММ:СС)
                dt = datetime.fromisoformat(timestamp)
                # Конвертируем в локальный часовой пояс компьютера
                # Если вызвать .astimezone() без аргументов,
                # Python автоматически возьмет системную таймзону
                local_dt = dt.astimezone()
                local_time = local_dt.strftime("%H:%M:%S")
            else:
                local_time = time.strftime("%H:%M:%S")
            # Формируем читаемый текст в зависимости от структуры поля data
            if 'message' in data_field:
                message = data_field['message']
            else:
                message = data_field

            # Собираем финальную строку для вывода
            formatted_message = f'[{local_time}] [{notice_type}] {message}'

            # обновление регионов сервера
            if notice_type == 'AvailableEgressRegions':
                Psiphon.regions = ['ANY'] + message['regions']

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            #print(line, e)
            # Если пришла битая строка или не JSON, выводим её как есть без цвета
            formatted_message = line.strip()
            notice_type = 'Raw'

        return formatted_message + '\n', notice_type

    def log_raw_message(self, text):
        # из plain text в json
        return self.log_message(f'{{"data": "{text}"}}')

    def check_and_update(self):
        # Создаем подкаталог PSIPHON_DIR, если его еще нет
        #PSIPHON_DIR.mkdir(parents=True, exist_ok=True)
        # Заголовки http-запроса
        headers = {}
        # Проверяем наличие файла и сохраненного ETag
        if PSIPHON_PATH.exists() and PSIPHON_ETAG_FILE.exists():
            saved_etag = PSIPHON_ETAG_FILE.read_text(encoding="utf-8").strip()
            headers["If-None-Match"] = saved_etag

        try:
            response = requests.head(PSIPHON_URL, headers=headers, allow_redirects=True)
            response.raise_for_status()
            if response.status_code == 304:
                self.log_raw_message("Обновлений нет. Локальный файл актуален.")
                return

            try:
                # Если файл существует, переименовываем его в .old
                if PSIPHON_PATH.exists():
                    old_path = PSIPHON_PATH.with_suffix('.old')
                    # Если старый .old уже остался от прошлых разов, удаляем его
                    if old_path.exists():
                        old_path.unlink()
                    PSIPHON_PATH.rename(old_path)
                # Скачиваем файл частями
                response = requests.get(PSIPHON_URL, stream=True)
                response.raise_for_status()
                with open(PSIPHON_PATH, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

            except OSError as e:
                self.log_raw_message(f'Ошибка обновления psiphon: {e}')
                return

            # Права на запуск актуальны только для UNIX-систем
            if sys.platform != "win32":
                try:
                    PSIPHON_PATH.chmod(0o755)
                except OSError:
                    pass

            self.log_raw_message(f"Файл успешно обновлен и сохранен в: {PSIPHON_PATH}")

            new_etag = response.headers.get("ETag")
            if new_etag:
                PSIPHON_ETAG_FILE.write_text(new_etag, encoding="utf-8")

        except requests.exceptions.RequestException as e:
            self.log_raw_message(f"Ошибка при проверке обновлений: {e}")



class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('AMProxy Runner')
        self.geometry('800x600')

        # Панель вкладок
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)
        self.setup_main_tab()
        self.setup_config_tab()
        self.setup_control_tab()
        # AMProxy
        self.amproxy = AMProxy(self)
        # Psiphon
        self.psiphon = Psiphon(self)

        self.load_config()
        self.control_entry.load_history()
        # Корректное закрытие приложения
        self.protocol('WM_DELETE_WINDOW', self.on_closing)
        self.bind('<Control-q>', self.on_closing)
        self.bind('<Command-q>', self.on_closing)

        self.psiphon.check_and_update()

        if self.amproxy_autostart.get():
            self.amproxy.start()
        if self.psiphon_autostart.get():
            self.psiphon.start()

        #self.after(0, self.check_port)

    def setup_main_tab(self):
        main_tab = ttk.Frame(self.notebook)
        self.notebook.add(main_tab, text=' Main ')
        ttk.Button(
            main_tab, text='Run', command=self.run_server
        ).pack(pady=20)

    def setup_control_tab(self):
        control_tab = ttk.Frame(self.notebook)
        self.notebook.add(control_tab, text=' Control ')
        # Информационный Label
        ttk.Label(
            control_tab, text=(
                'Управление AMProxy\n'
                '• Для получения списка команд нажмите «TAB»\n'
                '• Для получения краткой справки по командам введите «help»'
            ), justify='left',
        ).pack(padx=15, pady=15, fill='x')
        # Команда
        frame = ttk.Frame(control_tab)
        frame.pack(fill='x', padx=15)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, padding=4, text='Команда:').grid(row=0, column=0, sticky='ew')
        self.control_entry = HistoryEntry(frame, self.send_control_command,
                                          self.get_commands)
        self.control_entry.grid(row=0, column=1, sticky='ew', padx=(5,20))
        # Checkbutton "Очищать"
        self.clear_control_text = tk.BooleanVar()
        ttk.Checkbutton(
            control_tab, text='Очищать', variable=self.clear_control_text,
        ).pack(anchor='w', padx=15, pady=5)
        # Labelframe "Ответ AMProxy"
        frame = ttk.Labelframe(control_tab, text='Ответ AMProxy', padding=10)
        frame.pack(padx=15, pady=5, fill='both', expand=True)
        # Скроллбар и текстовое поле
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side='right', fill='y')
        self.control_text = tk.Text(
            frame, wrap='char', state='disabled',
            bg='#1e1e1e', fg='#ffffff', yscrollcommand=scrollbar.set)
        self.control_text.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.control_text.yview)

    def add_control_text(self, text, clear=True):
        self.control_text.config(state='normal')
        if clear and self.clear_control_text.get():
            self.control_text.delete(1.0, 'end')
        self.control_text.insert('end', text)
        self.control_text.see('end')
        self.control_text.config(state='disabled')

    def send_control_command(self, cmd, is_autocomplete=False):
        if not cmd:
            return
        if is_autocomplete:
            self.add_control_text(' '.join(cmd)+'\n')
            return
        self.add_control_text(f'Отправлена команда «{cmd}»\n')
        # Запрос серверу в отдельном потоке, чтобы не замораживать GUI
        threading.Thread(
            target=self._safe_send_command, args=(cmd,), daemon=True
        ).start()

    def _safe_send_command(self, cmd):
        # Фоновая работа с сервером
        self.control_entry.insert(0, 'Please wait')
        self.control_entry.config(state='disabled')
        response = send_command(cmd, '127.0.0.1', int(self.control_port.get()))+'\n'
        self.add_control_text(response, False)
        self.control_entry.config(state='enabled')
        self.control_entry.delete(0, 'end')

    def get_commands(self):
        response = send_command('commands', '127.0.0.1', int(self.control_port.get()))
        return response.split()

    def setup_config_tab(self):
        def _entry(text, width):
            ttk.Label(frame, padding=4, text=f'{text}:'
                      ).grid(row=i, column=0, sticky='w')
            en = Entry(frame, width=width)
            en.grid(row=i, column=1, sticky='w')
            return en
        def _checkb(text, var):
            ttk.Checkbutton(frame, padding=4, text=text, variable=var,
                            ).grid(row=i, column=0, columnspan=3, sticky='w')

        config_tab = ttk.Frame(self.notebook)
        self.notebook.add(config_tab, text=' Config ')
        config_frame = ttk.Frame(config_tab)
        config_frame.pack(padx=10, pady=10, expand=True, fill='both')

        # 1. Верхний информационный Label
        ttk.Label(
            config_frame, text=(
                'Настройки AMProxy\n'
                '• Для перезапуска сервера нажмите «Применить»\n'
                '• Для возвращения к настройкам по умолчанию нажмите «Сбросить настройки»'
            ), justify='left',
        ).pack(padx=15, pady=15, fill='x')

        # 2. Labelframe 'Настройки AMProxy'
        frame = ttk.Labelframe(config_frame, text='Настройки AMProxy', padding=10)
        frame.pack(padx=15, pady=5, fill='x')
        i = 0
        self.amproxy_host = _entry('Хост', 12)
        i += 1
        self.amproxy_port = _entry('Порт', 6)
        i += 1
        self.control_port = _entry('Порт управления', 6)
        i += 1
        self.amproxy_autostart = tk.BooleanVar()
        _checkb('Автоматически запускать AMProxy при старте', self.amproxy_autostart)

        # 3. Labelframe 'Настройки Psiphon'
        frame = ttk.Labelframe(config_frame, text='Настройки Psiphon', padding=10)
        frame.pack(padx=15, pady=5, fill='x')
        i = 0
        self.psiphon_host = _entry('Хост', 12)
        i += 1
        self.psiphon_socks5_port = _entry('Socks5 порт', 6)
        i += 1
        self.psiphon_http_port = _entry('HTTP порт', 6)
        i += 1
        ttk.Label(frame, padding=4, text='Регион сервера:'
                  ).grid(row=i, column=0, sticky='w')
        self.psiphon_regions = ttk.Combobox(frame, values=Psiphon.regions,
                                            state='readonly')
        self.psiphon_regions.current(0) # Делаем первый элемент (ANY) выбранным по умолчанию
        self.psiphon_regions.grid(row=i, column=1, columnspan=2, sticky='w')
        i += 1
        self.random_port = tk.BooleanVar()
        _checkb('Использовать случайный порт', self.random_port)
        i += 1
        self.psiphon_autostart = tk.BooleanVar()
        _checkb('Автоматически запускать Psiphon при старте', self.psiphon_autostart)

        # # 4. Labelframe 'Дополнительные настройки AMProxy'
        # frame = ttk.Labelframe(config_frame, text='Дополнительные настройки AMProxy',
        #                        padding=10)
        # frame.pack(padx=15, pady=5, fill='both', expand=True)
        # # Скроллбар и текстовое поле
        # scrollbar = ttk.Scrollbar(frame)
        # scrollbar.pack(side='right', fill='y')
        # self.text_area = tk.Text(frame, yscrollcommand=scrollbar.set, height=6)
        # self.text_area.pack(side='left', fill='both', expand=True)
        # scrollbar.config(command=self.text_area.yview)

        # 5. Кнопки "Применить" и "Сбросить настройки" в самом низу
        frame = ttk.Frame(config_frame)
        frame.pack(side='bottom', pady=15)
        ttk.Button(frame, text='Применить', width=15, command=self.apply_config
                   ).pack(padx=10, side='left')
        ttk.Button(frame, text='Сбросить настройки', width=20,
                   command=self.set_default_config
                   ).pack(padx=10, side='left')

        self.set_default_config()

    def set_default_config(self):
        self.amproxy_autostart.set(False)
        self.amproxy_host.replace('127.0.0.1')
        self.amproxy_port.replace('8888')
        self.control_port.replace('9999')
        self.psiphon_autostart.set(False)
        self.random_port.set(True)
        self.psiphon_host.replace('127.0.0.1')
        self.psiphon_http_port.replace('8080')
        self.psiphon_socks5_port.replace('1080')

    def run_server(self):
        if self.amproxy.process is None:
            self.amproxy.start()
        if self.psiphon.process is None:
            self.psiphon.start()

    def apply_config(self):
        self.amproxy.stop()
        self.psiphon.stop()
        # чтобы не замораживать GUI и дождаться завершения процессов
        self.after(4000, self.restart)

    def restart(self):
        if self.amproxy.process is None:
            self.amproxy.start()
        if self.psiphon.process is None:
            self.psiphon.start()

    def on_closing(self, event=None):
        # Если пользователь закрыл окно
        try:
            self.psiphon.stop()
        except Exception as e:
            print(e)
        try:
            self.amproxy.stop()
        except Exception as e:
            print(e)

        self.save_config()
        self.control_entry.save_history()
        self.destroy()

    # Функция проверки доступности порта
    def check_port(self):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                # Если подключение успешно, порт занят (сервер работает)
                result = s.connect_ex(('127.0.0.1', self.amproxy.port))
                if result == 0:
                    self.status_label.config(text='Работает', fg='green')
                else:
                    self.status_label.config(text='Не работает', fg='red')
            time.sleep(10)  # Проверяем каждую секунду

    def save_config(self):
        config = ConfigParser()
        config['Window'] = {
            'geometry': self.geometry(),
        }
        config['AMProxy'] = {
            'autostart': str(self.amproxy_autostart.get()),
            'host': str(self.amproxy_host.get()),
            'port': str(self.amproxy_port.get()),
            'control port': str(self.control_port.get()),
        }
        config['Psiphon'] = {
            'autostart': str(self.psiphon_autostart.get()),
            'random port': str(self.random_port.get()),
            'host': str(self.psiphon_host.get()),
            'http port': str(self.psiphon_http_port.get()),
            'socks5 port': str(self.psiphon_socks5_port.get()),
            'regions': ' '.join(Psiphon.regions),
            'selected region': self.psiphon_regions.get(),
        }
        with open(GUI_CONFIG, 'w') as configfile:
            config.write(configfile)

    def load_config(self):
        config = ConfigParser()
        config.read(GUI_CONFIG)
        if 'Window' in config:
            if 'geometry' in config['Window']:
                self.geometry(config['Window']['geometry'])
        if 'AMProxy' in config:
            section = config['AMProxy']
            if 'autostart' in section:
                self.amproxy_autostart.set(section.getboolean('autostart'))
            if 'host' in section:
                self.amproxy_host.replace(section['host'])
            if 'port' in section:
                self.amproxy_port.replace(section['port'])
            if 'control port' in section:
                self.control_port.replace(section['control port'])
        if 'Psiphon' in config:
            section = config['Psiphon']
            if 'autostart' in section:
                self.psiphon_autostart.set(section.getboolean('autostart'))
            if 'random port' in section:
                self.random_port.set(section.getboolean('random port'))
            if 'host' in section:
                self.psiphon_host.replace(section['host'])
            if 'http port' in section:
                self.psiphon_http_port.replace(section['http port'])
            if 'socks5 port' in section:
                self.psiphon_socks5_port.replace(section['socks5 port'])
            if 'regions' in section:
                regions = section['regions'].split()
                self.psiphon_regions['values'] = regions
            if 'selected region' in section:
                self.psiphon_regions.set(section['selected region'])


if __name__ == '__main__':
    app = App()
    app.mainloop()

#
