#!/usr/bin/env python
import sys
from glob import glob

help = '''Использование:
  -a domain    удалить domain из всех файлов кэша
  -r domain    удалить domaim из rules.txt
  -d domain    удалить domaim из direct.txt
  -f domain    удалить domaim из failed.txt
  -h domain    удалить domaim из history.txt
  -t           только показать найденные строки (тестовый режим)
'''
test = False
msg = 'удалено из'
if '-t' in sys.argv:
    print('тестовый режим')
    sys.argv.remove('-t')
    test = True
    msg = 'найдено в'

if len(sys.argv) != 3:
    sys.exit(help)

def del_line(filename, s):
    with open(filename) as f:
        lines = f.readlines()
    res = []
    found = False
    for line in lines:
        if s not in line:
            res.append(line)
        else:
            found = True
            print(f'{msg} {filename}: {line}', end='')
    if found and not test:
        with open(filename, 'w') as f:
            f.write(''.join(res))

if sys.argv[1] == '-a':
    files = ['cache/direct.txt', 'cache/failed.txt',
             'cache/rules.txt', 'cache/history.txt'] + \
             glob('cache/*/direct.txt') + glob('cache/*/failed.txt') + \
             glob('cache/*/rules.txt') + glob('cache/*/history.txt')
elif sys.argv[1] == '-d':
    files = ['cache/direct.txt'] + glob('cache/*/direct.txt')
elif sys.argv[1] == '-f':
    files = ['cache/failed.txt'] + glob('cache/*/failed.txt')
elif sys.argv[1] == '-r':
    files = ['cache/rules.txt'] + glob('cache/*/rules.txt')
elif sys.argv[1] == '-h':
    files = ['cache/history.txt'] + glob('cache/*/history.txt')
else:
    sys.exit(help)

for filename in files:
    del_line(filename, sys.argv[2])




