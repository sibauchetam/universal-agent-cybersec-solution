# Universal Cybersecurity Agent — решение Universal Agent Competition

Универсальный LLM-агент для соревнования [SecureIntelligent/UniversalAgenticCompetitionPublic](https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic): аудита уязвимостей, SWE-стиль исправлений, цифровой форензики и CTF-задач на **малых локальных LLM** (целевая модель — `qwen/qwen3.6-35b-a3b` на OpenRouter; ранняя валидация шла на qwen3.6-27b через Groq), без интернета, с ограниченным бюджетом запросов.

**Английское резюме:** This repo contains a competition-ready cybersecurity agent (`submission/`), 23 runnable synthetic tasks + 23 design specs simulating the private task set (MITRE ATT&CK + OWASP Top 10:2025), a local validation harness, and a research digest of 32 AlphaXiv papers (2 rounds; 14 detailed digests) that shaped the design. See `docs/` for details.

## Структура

```
submission/         — пакет сабмита (run.sh + sec_agent.py), кладётся в zip
synthetic_tasks/    — 23 runnable задачи, полный симулякр приватного набора (5 audit / 8 fix / 7 forensics / 3 ctf)
docs/
  synthetic-task-specs/ — 23 спецификации (дизайн-раунд 1 — 12, дизайн-раунд 2 — 11), каждая 1:1 с runnable-задачей
  research.md        — дайджест 14 статей с AlphaXiv, сформировавших дизайн
  papers.md          — 32 отобранные статьи (2 раунда): суть, цифры, что внедрено в sec_agent.py
  architecture.md    — архитектура агента и обоснование решений
  results.md         — протокол локальной валидации
harness/            — локальный тестовый харнесс (OpenRouter/Groq, провайдер-скоуп ключей, rate limiting)
```

### Покрытие синтетического набора (23 задачи)

| Категория | Кол-во | Примеры |
|---|---|---|
| audit (bug-bounty JSON-отчёт) | 5 | find-ssrf-webhook, find-supply-chain-backdoor, find-logging-gaps |
| fix (SWE-стиль, pytest должен оставаться зелёным) | 8 | fix-insecure-pickle, fix-jwt-none-alg, fix-giftcard-negative-transfer |
| forensics (key=value инцидент-отчёт) | 7 | bruteforce-ssh-forensics, log-tamper-forensics, webshell-hunt-forensics |
| ctf (флаг-хант) | 3 | staged-files-flag, credential-stash-flag, persistence-hunt-host |

Сложности: 6 easy / 11 medium / 6 hard. Покрытие MITRE ATT&CK — 14 техник (T1005, T1021.004, T1036, T1041, T1046, T1048, T1053, T1070, T1110, T1136.001, T1505.003, T1543, T1552, T1562.001). Покрытие OWASP Top 10:2025 — 8 из 10 категорий (A01, A02, A03, A06, A07, A08, A09, A10).

## Быстрый старт (локальная валидация)

```bash
export OPENAI_API_KEY=...            # ключ OpenAI-совместимого endpoint (OpenRouter/Groq/vLLM/...)
export OPENAI_BASE_URL=https://openrouter.ai/api/v1   # или https://api.groq.com/openai/v1
export LOCAL_AGENT_MODEL=qwen/qwen3.6-35b-a3b         # groq: qwen/qwen3.6-27b
# опционально: SEC_AGENT_PROXY_URL=socks5://... SEC_AGENT_RPM=30

python3 submission/sec_agent.py "Create a file at /app/hello.txt whose entire content is exactly the single word Hello"
```

Сам агент (`submission/`) провайдеро-агностичен: читает `OPENAI_BASE_URL` / `OPENAI_API_KEY` / `LOCAL_AGENT_MODEL` из окружения — в заезде их выставляет инфраструктура соревнования.

Харнесс: `harness/harness.py --provider openrouter|groq` (по умолчанию **openrouter**). Ключи скоупятся по провайдеру (чужой ключ не уйдёт в чужой endpoint): openrouter — `OPENROUTER_API_KEY`; groq — `GROQ_API_KEY_1/2` + SOCKS5-прокси `GROQ_PROXY`. Модели по умолчанию: openrouter — `qwen/qwen3.6-35b-a3b`, groq — `qwen/qwen3.6-27b` (переопределяются `LOCAL_AGENT_MODEL`). Прокси openrouter: `OPENROUTER_PROXY` (пусто = напрямую, endpoint доступен без прокси).

## Ключевые результаты

| Механика | Эффект (по статьям) |
|---|---|
| Типизированный pytest-feedback вместо сырого traceback | +42–44pp решаемости на моделях 8B–14B (VeriHarness, arXiv:2607.14167) |
| Double-внешняя верификация (PoC blocked + tests green) | ловит 12.6% «успешных» патчей, ломающих функциональность (Vul4Py, arXiv:2608.00692) |
| Fast-path для тривиальных задач | 0 LLM-запросов, 0.2с на hello/bye-file |
| Response-normalizing транспорт | чинит валидацию pydantic-ai 1.x против Groq/нестандартных OpenAI-совместимых серверов (безвреден для OpenRouter) |
| replace_in_file вместо unified diff | малые модели надёжно копируют контекст, чем генерят диффы |

Подробности: `docs/architecture.md`, `docs/research.md`, `docs/papers.md`.
