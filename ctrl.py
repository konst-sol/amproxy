#!/usr/bin/env python3
# -*- mode: python; coding: utf-8; -*-

import socket
import argparse
import sys

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

def main():
    # Настраиваем парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description='Утилита для управления прокси-сервером.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Примеры использования:\n'
               '  python ctrl.py reload\n'
               '  python ctrl.py status --host 192.168.1.50 --port 9999'
    )
    # Обязательный аргумент — сама команда
    parser.add_argument(
        'command', 
        #choices=['reload', 'status'], 
        help='Команда для отправки на прокси-сервер'
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
        default=0,
        help='Порт управляющего сервера'
    )
    args = parser.parse_args()
    if args.port:
        port = args.port
    else:
        try:
            import amproxy
        except ImportError:
            print('ERROR: Не удалось импортировать amproxy. '
                  'Укажите порт управляющего сервера в коммандной строке',
                  file=sys.stderr)
            sys.exit(1)
        else:
            amproxy.info=lambda x: None
            amproxy.read_config_file()
            port = amproxy.CONTROL_PORT
            if not port:
                print('ERROR: Укажите порт управляющего сервера в конфиг-файле '
                      '(например CONTROL_PORT=9999) и перезапустите прокси-сервер',
                      file=sys.stderr)
                sys.exit(1)

    # Отправляем команду
    print(f'Отправка команды {args.command} на {args.host}:{port}...')
    send_command(args.command, args.host, port)

if __name__ == '__main__':
    main()

#
