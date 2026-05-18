#!/usr/bin/env python3
# -*- mode: python; coding: utf-8; -*-

import sys, os
import socket
import argparse
from configparser import ConfigParser

def send_command(command, host, port):
    '''Отправляет текстовую команду на управляющий порт прокси-сервера.'''
    try:
        # Создаем TCP-сокет
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Устанавливаем таймаут, чтобы утилита не зависла, если сервер мертв
            sock.settimeout(3.0)
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
            print(response)
    except socket.timeout:
        print(f'ERROR: Превышено время ожидания ответа от {host}:{port}',
              file=sys.stderr)
        sys.exit(1)
    except ConnectionRefusedError:
        print(f'ERROR: Не удалось подключиться к {host}:{port}. Прокси-сервер запущен?',
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'ERROR: Произошла непредвиденная ошибка: {e}', file=sys.stderr)
        sys.exit(1)

def get_port_from_config(config_path):
    config = ConfigParser(interpolation=None)
    config.read((config_path), encoding='utf-8')
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
    parser = argparse.ArgumentParser(
        description='Утилита для управления прокси-сервером.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Для получения списка команд отправьте help:\n  python ctrl.py help\n'
    )
    # Обязательный аргумент — сама команда
    parser.add_argument(
        'command',
        nargs='+',
        help='Команда прокси-серверу'
    )
    # Необязательные аргументы для смены хоста и порта
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help=f'IP-адрес управляющего сервера (по умолчанию: 127.0.0.1)'
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
    args = parser.parse_args()
    if args.port:
        port = args.port
    elif args.config:
        if not os.path.isfile(args.config):
            print(f'ERROR: конфиг-файл {args.config} не найден')
            sys.exit(1)
        port = get_port_from_config(args.config)
        if not port:
            print(f'ERROR: опция control_port в конфиг-файле {args.config} не найдена')
            sys.exit(1)
        port = int(port)
    else:
        try:
            import amproxy
        except ImportError:
            print('ERROR: Не удалось импортировать amproxy. '
                  'Укажите в командной строке порт управляющего сервера (-p) '
                  'или путь к конфиг-файлу (-c)',
                  file=sys.stderr)
            sys.exit(1)
        else:
            amproxy.read_config_file()
            print(f'Определение порта из {amproxy.CONFIG_PATH}')
            port = amproxy.CONTROL_PORT
            if not port:
                print('ERROR: Укажите порт управляющего сервера в конфиг-файле '
                      '(например CONTROL_PORT=9999) и перезапустите прокси-сервер',
                      file=sys.stderr)
                sys.exit(1)

    # Отправляем команду
    command = ' '.join(args.command)
    print(f'Отправка команды {command} на {args.host}:{port}...')
    send_command(command, args.host, port)

if __name__ == '__main__':
    main()

#
