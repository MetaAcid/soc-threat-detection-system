# SOC Threat Detection System

Python-проект, имитирующий базовые задачи SOC-аналитика: анализ логов, обнаружение угроз и генерация алертов.

## Функциональность

Система анализирует:
- Linux auth logs
- Web access logs

Обнаруживает:
- brute-force атаки
- повторяющиеся неуспешные попытки входа
- path scanning / reconnaissance
- всплески серверных ошибок (5xx)
- подозрительную активность по IP

## Структура проекта

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