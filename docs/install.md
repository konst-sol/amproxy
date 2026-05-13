# Инструкция по установке
Данная инструкция описывает настройку окружения для запуска программы `amproxy.py`. Метаданные в файле соответствуют стандарту PEP 723 (Script Dependencies).

## Системные требования
* Python: Версия 3.9 или выше.
* Операционная система: Windows, Linux или macOS.
* Интернет: для загрузки внешних пакетов.

## Способ 1: Использование uv (рекомендуемый)
Утилита `uv` автоматически считывает метаданные PEP 723, создает временное окружение и запускает программу одной командой без ручной установки зависимостей.

1. Установите uv:
   1. Windows: `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
   2. Linux/macOS: `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. Запустите программу: `uv run amproxy.py`

## Способ 2: Использование pipx (для запуска в изолированном окружении)
Этот метод изолирует зависимости программы от глобальной системы.

1. Установите pipx:
   1. `pip install pipx`
   2. `pipx ensurepath`
2. Запустите программу:\
`pipx run amproxy.py`

## Способ 3: Классический метод (pip + виртуальное окружение)
Стандартный подход с явным созданием окружения внутри папки проекта.

1. Создайте виртуальное окружение: `python -m venv .venv`
2. Активируйте окружение:
   1. Windows (Cmd): `.venv\Scripts\activate.bat`
   2. Windows (PowerShell): `.venv\Scripts\Activate.ps1`
   3. Linux/macOS: `source .venv/bin/activate`
3. Установите зависимости: `pip install curl-cffi pysocks beautifulsoup4 requests`
4. Запустите программу: `python amproxy.py`

## Способ 4: Глобальная установка (не рекомендуется)
Используйте этот метод только в Docker-контейнерах или изолированных тестовых машинах.

Установите модули напрямую: `pip install curl-cffi pysocks beautifulsoup4 requests`

Запустите программу: `python amproxy.py`

