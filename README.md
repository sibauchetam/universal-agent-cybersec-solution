# Universal Cybersecurity Agent — решение Universal Agent Competition

Универсальный LLM-агент для соревнования [SecureIntelligent/UniversalAgenticCompetitionPublic](https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic): аудита уязвимостей, SWE-стиль исправлений, цифровой форензики и CTF-задач на **малых локальных LLM** (qwen3.6-27b и близких), без интернета, с ограниченным бюджетом запросов.

**Английское резюме:** This repo contains a competition-ready cybersecurity agent (`submission/`), 3 runnable + 23 specced synthetic tasks simulating the private task set (MITRE ATT&CK + OWASP Top 10:2025), a local validation harness, and a research digest of 32 AlphaXiv papers (2 rounds) that shaped the design. See `docs/` for details.

## Структура

```
submission/         — пакет сабмита (run.sh + sec_agent.py), кладётся в zip
synthetic_tasks/    — 3 runnable задачи (fix-insecure-pickle, bruteforce-ssh-forensics, staged-files-flag)
docs/
  synthetic-task-specs/ — 23 спецификации приватных задач (9+ требовалось, сделано 23: дизайн-раунд 1 — 12, дизайн-раунд 2 — 11)
  research.md        — дайджест 14 статей с AlphaXiv + как каждая влияет на дизайн
  architecture.md    — архитектура агента и обоснование решений
  results.md         — протокол локальной валидации
harness/            — локальный тестовый харнесс (Groq-совместимый endpoint, rate limiting)
```

## Быстрый старт (локальная валидация)

```bash
export OPENAI_API_KEY=...            # ключ OpenAI-совместимого endpoint (Groq/vLLM/...)
export OPENAI_BASE_URL=https://api.groq.com/openai/v1
export LOCAL_AGENT_MODEL=qwen/qwen3.6-27b
# опционально: SEC_AGENT_PROXY_URL=socks5://... SEC_AGENT_RPM=30

python3 submission/sec_agent.py "Create a file at /app/hello.txt whose entire content is exactly the single word Hello"
```

Харнесс: `harness/harness.py` (переменные читаются из окружения: `GROQ_API_KEY_1/2`, `GROQ_PROXY`, `OPENAI_BASE_URL`, `LOCAL_AGENT_MODEL`).

## Ключевые результаты

| Механика | Эффект (по статьям) |
|---|---|
| Типизированный pytest-feedback вместо сырого traceback | +42–44pp решаемости на моделях 8B–14B (VeriHarness, arXiv:2607.14167) |
| Double-внешняя верификация (PoC blocked + tests green) | ловит 12.6% «успешных» патчей, ломающих функциональность (Vul4Py, arXiv:2608.00692) |
| Fast-path для тривиальных задач | 0 LLM-запросов, 0.2с на hello/bye-file |
| Response-normalizing транспорт | чинит валидацию pydantic-ai 1.x против Groq/нестандартных OpenAI-совместимых серверов |
| replace_in_file вместо unified diff | малые модели надёжно копируют контекст, чем генерят диффы |

Подробности: `docs/architecture.md`, `docs/research.md`, `docs/papers.md`.
