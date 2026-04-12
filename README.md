# Skills Verified

AI Agent Trust Scanner — CLI-утилита для сертификации репозиториев AI-агентов. Анализирует код на уязвимости, CVE, prompt injection и проблемы supply chain, выдаёт итоговый **Trust Score** (грейд A-F).

## Что проверяет

| Категория | Что ищет |
|---|---|
| **Code Safety** | `eval`, `exec`, `compile`, `shell=True`, `os.system`, `pickle.load`, `yaml.load`, hardcoded secrets |
| **CVE** | Известные уязвимости в зависимостях (через `pip-audit` и `npm audit`) |
| **Guardrails** | Prompt injection, jailbreak-паттерны (DAN/STAN/developer mode), скрытые Unicode, base64-инъекции |
| **Permissions** | Деструктивные операции с файлами, сетевые вызовы, запуск процессов |
| **Supply Chain** | Typosquatting, опасные `postinstall`-скрипты, код в `setup.py` |

Дополнительно: обёртки над **Bandit** и **Semgrep**, опциональный семантический анализ через **LLM** (OpenAI-совместимый API).

## Установка

```bash
git clone <repo-url> skills-verified
cd skills-verified
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Для LLM-анализа:
```bash
pip install -e ".[llm]"
```

Опциональные внешние инструменты (устанавливаются отдельно, утилита работает и без них):
```bash
pip install bandit semgrep pip-audit
```

## Использование

```bash
# Базовый запуск — GitHub URL
skills-verified https://github.com/user/repo

# Локальный путь
skills-verified /path/to/local/repo

# JSON-отчёт
skills-verified https://github.com/user/repo --output report.json

# Пропустить отдельные анализаторы
skills-verified https://github.com/user/repo --skip bandit,semgrep

# Запустить только нужные
skills-verified https://github.com/user/repo --only guardrails,supply_chain

# С LLM-анализом (OpenAI-совместимый API)
skills-verified https://github.com/user/repo \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-4o \
  --llm-key sk-xxx
```

### Переменные окружения

```bash
export SV_LLM_URL=https://api.openai.com/v1
export SV_LLM_MODEL=gpt-4o
export SV_LLM_KEY=sk-xxx
```

Приоритет: CLI-флаги > env-переменные.

## Trust Score

Каждая категория стартует со 100 баллов. Штрафы по severity:

| Severity | Штраф |
|---|---|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -7 |
| LOW | -3 |

Общий балл — среднее по 5 категориям. Грейды:

| Балл | Грейд |
|---|---|
| 90-100 | **A** |
| 80-89 | **B** |
| 65-79 | **C** |
| 50-64 | **D** |
| 0-49 | **F** |

## Пример вывода

```
╭──────────────────────────────────────────────────────────────╮
│ Skills Verified — AI Agent Trust Scanner                     │
╰──────────────────────────────────────────────────────────────╯

  Repository: https://github.com/user/repo
  Analyzers:  pattern, guardrails, permissions, supply_chain

╭──────────────────────────────────────────────────────────────╮
│   TRUST SCORE:  D  (60/100)                                  │
╰──────────────────────────────────────────────────────────────╯
  Code Safety     F (0)      43 findings
  Cve             A (100)     0 findings
  Guardrails      A (100)     0 findings
  Permissions     F (0)      34 findings
  Supply Chain    A (100)     0 findings

  CRITICAL (6) | HIGH (56) | MEDIUM (13) | LOW (2)

  [CRITICAL] Unsafe eval() call
    pattern | scripts/browser.mjs:2805
    eval() executes arbitrary code and should not be used...
  ...
```

## Архитектура

Pipeline с плагинами. Каждый анализатор реализует интерфейс `Analyzer` (`is_available()`, `analyze(repo_path) -> list[Finding]`). Pipeline собирает находки, Scorer вычисляет грейды, вывод идёт через Rich-консоль и/или JSON.

```
src/skills_verified/
├── cli.py                  # Click CLI
├── core/
│   ├── models.py           # Finding, Severity, Category, Grade, Report
│   ├── analyzer.py         # ABC Analyzer
│   ├── pipeline.py         # Оркестратор
│   └── scorer.py           # Подсчёт баллов и грейдов
├── analyzers/
│   ├── pattern_analyzer.py
│   ├── cve_analyzer.py
│   ├── bandit_analyzer.py
│   ├── semgrep_analyzer.py
│   ├── guardrails_analyzer.py
│   ├── permissions_analyzer.py
│   ├── supply_chain_analyzer.py
│   └── llm_analyzer.py
├── repo/fetcher.py         # git clone / локальный путь
└── output/
    ├── console.py          # Rich-вывод
    └── json_report.py      # JSON-отчёт
```

## Разработка

```bash
# Тесты
pytest tests/ -v

# С покрытием
pytest tests/ --cov=skills_verified --cov-report=term-missing

# Линтинг
ruff check src/ tests/
```

## Структура JSON-отчёта

```json
{
  "repo_url": "https://github.com/user/repo",
  "overall_score": 60,
  "overall_grade": "D",
  "categories": [
    {
      "category": "code_safety",
      "score": 0,
      "grade": "F",
      "findings_count": 43,
      "critical_count": 6,
      "high_count": 37
    }
  ],
  "findings": [
    {
      "title": "Unsafe eval() call",
      "description": "eval() executes arbitrary code...",
      "severity": "critical",
      "category": "code_safety",
      "file_path": "scripts/browser.mjs",
      "line_number": 2805,
      "analyzer": "pattern",
      "cve_id": null,
      "confidence": 1.0
    }
  ],
  "analyzers_used": ["pattern", "guardrails", "permissions", "supply_chain"],
  "llm_used": false,
  "scan_duration_seconds": 3.49
}
```

## Лицензия

MIT
