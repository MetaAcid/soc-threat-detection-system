# SOC Threat Detection System

Python-проект, имитирующий базовые задачи SOC-аналитика: анализ логов, обнаружение угроз и генерация алертов.

---

## Описание

Система анализирует журналы событий (лог-файлы) и выявляет подозрительную активность, характерную для атак:

- brute-force попытки входа
- reconnaissance (сканирование путей)
- аномалии в логах
- всплески серверных ошибок

Проект моделирует реальные задачи SOC:
- мониторинг событий безопасности
- triage алертов
- выявление инцидентов

Стандартный запуск:
- python src/main.py

Запуск с параметрами:
- python src/main.py --auth logs/auth.log --access logs/access.log --output output/alerts.json
---

## Функциональность

Поддерживаемые источники логов:
- Linux auth logs (SSH)
- Web access logs

Обнаруживаемые угрозы:

- Brute Force  
  Множественные неудачные попытки входа с одного IP

- Suspicious Authentication Activity  
  Повторяющиеся попытки входа

- Path Scanning / Reconnaissance  
  Попытки доступа к чувствительным путям (`/admin`, `/.env`, и др.)

- Server Error Spike  
  Резкий рост 5xx ошибок

- Suspicious Repeated Activity  
  Аномально большое количество запросов с одного IP

---

## Пример вывода

=== ALERTS DETECTED ===

[1] Brute Force
Severity   : HIGH
Source IP  : 192.168.1.10
Timestamp  : N/A
Description: Detected 6 failed login attempts from 192.168.1.10

[2] Path Scanning / Reconnaissance
Severity   : HIGH
Source IP  : 192.168.1.30
Description: Detected reconnaissance activity from 192.168.1.30 with 5 suspicious requests

---

## Выходные данные

Программа сохраняет результат в:
- output/alerts.json

Пример:
[
  {
    "type": "Brute Force",
    "severity": "HIGH",
    "source_ip": "192.168.1.10",
    "timestamp": "N/A",
    "description": "Detected 6 failed login attempts"
  }
]

---

## Возможные будующие улучшения

- интеграция с SIEM
- real-time обработка логов
- добавление ML для anomaly detection
- GeoIP анализ IP-адресов
- визуализация данных

---

## Архитектура

```text
soc-threat-detection-system/
├── logs/
│   ├── auth.log
│   └── access.log
├── output/
│   └── alerts.json
├── src/
│   ├── main.py
│   ├── log_parser.py
│   ├── detector.py
│   ├── rules.py
│   └── reporter.py
├── README.md
├── requirements.txt
└── .gitignore