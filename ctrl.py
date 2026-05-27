#!/usr/bin/env python3
# -*- mode: python; coding: utf-8; -*-

import sys, os
import socket
import argparse
import configparser

sys.dont_write_bytecode = True # чтобы не создавать __pycache__/ в текущем каталоге

def info(*args):
    print(*args, file=sys.stderr)
def error(*args):
    print(f'{sys.argv[0]}: ERROR:', *args, file=sys.stderr)

class CtrlArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Выводим стандартный блок использования (usage)
        self.print_usage(sys.stderr)
        # Выводим текст конкретной ошибки
        error(message)
        # Выводим подсказку
        info(f'Try "{self.prog} --help" for more information.')
        sys.exit(2)


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
            print(response) # ответ сервера выводим в stdout
    except socket.timeout:
        error(f'Превышено время ожидания ответа от {host}:{port}')
        sys.exit(1)
    except ConnectionRefusedError:
        error(f'Не удалось подключиться к {host}:{port}. Прокси-сервер запущен?')
        sys.exit(1)
    except Exception as err:
        error(f'Произошла непредвиденная ошибка: {err}')
        sys.exit(1)

def get_port_from_config(config_path):
    config = configparser.ConfigParser(interpolation=None,
                                       inline_comment_prefixes=('#', ';'))
    try:
        config.read((config_path), encoding='utf-8')
    except configparser.Error as err:
        error(f'Ошибка чтения конфиг-файла: {type(err).__name__}: {err.message}')
        sys.exit(1)
    for section in config.sections():
        if 'control_port' in config[section]:
            port = config[section]['control_port']
            return port
    if 'control_port' in config.defaults():
        port = config.defaults()['control_port']
        return port
    return None

def main():
    # Настраиваем парсер аргументов командной строки
    parser = CtrlArgumentParser(
        add_help=False,
        description='Утилита для управления прокси-сервером.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Примеры:
  Вывести статистику использования стратегий:
    ctrl.py stats
  Удалить example.com из кэша:
    ctrl.py del example.com
  Установить для домена www.youtube.com стратегию -o1 -a1
  (используем "--" чтобы указать что опции для ctrl.py
  закончились и дальше идет команда серверу):
    ctrl.py -- set www.youtube.com -o1 -a1

Для получения полного списка команд отправьте help:
  ctrl.py help

NB: все служебные сообщения выводятся в stderr, а ответ сервера в stdout.

'''
    )
    # Обязательный аргумент — сама команда
    parser.add_argument(
        'command',
        nargs='+',
        help='Команда прокси-серверу'
    )
    # Необязательные аргументы для смены хоста и порта
    parser.add_argument(
        '-h', '--host',
        default='127.0.0.1',
        help='IP-адрес управляющего сервера (по умолчанию 127.0.0.1)'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        help='Порт управляющего сервера'
    )
    parser.add_argument(
        '-c', '--config',
        help='Путь к конфиг-файлу прокси'
    )
    # Вручную добавляем --help
    parser.add_argument(
        '--help', action='help', help='Показать это сообщение и выйти'
    )
    args = parser.parse_args()
    if args.port:
        port = args.port
    elif args.config:
        if not os.path.isfile(args.config):
            error(f'конфиг-файл {args.config} не найден')
            sys.exit(1)
        port = get_port_from_config(args.config)
        if not port:
            error(f'опция control_port в конфиг-файле {args.config} не найдена')
            sys.exit(1)
        port = int(port)
    else:
        try:
            import amproxy
        except ImportError:
            error('Не удалось импортировать amproxy. '
                  'Укажите в командной строке порт управляющего сервера (-p) '
                  'или путь к конфиг-файлу (-c)')
            sys.exit(1)
        else:
            amproxy.read_config_file()
            info(f'Определение порта из {amproxy.CONFIG_PATH}')
            port = amproxy.CONTROL_PORT
            if not port:
                error('Укажите порт управляющего сервера в конфиг-файле '
                      '(например CONTROL_PORT=9999) и перезапустите прокси-сервер')
                sys.exit(1)

    # Отправляем команду
    command = ' '.join(args.command)
    info(f'Отправка команды {command} на {args.host}:{port}...')
    send_command(command, args.host, port)

if __name__ == '__main__':
    main()

#
