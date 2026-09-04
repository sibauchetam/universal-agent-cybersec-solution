# Архитектура универсального кибербезопасность-агента

## Контекст соревнования

Harbor запускает `./run.sh "<instruction>"` внутри изолированной микроВМ без интернета.
Доступен только локальный LLM endpoint (`LOCAL_AGENT_MODEL`, `OPENAI_BASE_URL`,
`OPENAI_API_KEY`). Образ `secureintelligent/acp` содержит Python 3.12 и набор SDK:
pydantic-ai 1.44.0, openai, openai-agents, claude-agent-sdk, langgraph и др.
Скоринг бинарный per task; при равенстве решённых задач выше тот, кто быстрее и
экономнее по токенам.

## Выбор SDK

| SDK | Вердикт |
|---|---|
| **pydantic-ai 1.x** | Основной цикл: `UsageLimits(request_limit)` — жёсткий бюджет; `ModelRetry` — самокоррекция; `OpenAIProvider(openai_client=AsyncOpenAI(...))` — любой OpenAI-совместимый сервер и прокси из коробки; минимальный системный оверхед промпта |
| openai SDK (raw) | Fallback-цикл: полный контроль, устойчивость к поломкам pydantic-ai |
| openai-agents | Годен, но больше системного оверхеда (tracing/handoffs) |
| claude-agent-sdk | Непригоден: требует Claude Code CLI и Anthropic Messages API |

## Компоненты (`submission/sec_agent.py`, ~950 строк)

```
instruction ──> [0] fast-path (тривиальные файл-задачи) ──> записать файл, 0 запросов
      │
      └──> [1] классификация: механические ключи (детерминированно, бесплатно)
              └─ если generic ─> 1 крошечный LLM-запрос (audit|fix|forensics|ctf|generic)
      │
      └──> [2] baseline pytest (для fix-задач, механически)
      └──> [3] основной цикл pydantic-ai: 9 инструментов + workflow-промпт по типу задачи
               ├── bash, read_file(+номера строк), write_file, append_file
               ├── replace_in_file (точечная замена; при неудаче показывает ближайший фрагмент)
               ├── apply_patch, list_dir, grep (rg), run_pytest (типизированный feedback)
               └── UsageLimits(request_limit) + time budget
      └──> [4] механическая верификация deliverable
              └─ провал ─> repair-фаза (до 6 запросов, свежий цикл с причиной провала)
```

### Решения, обоснованные исследованиями (docs/research.md)

1. **Типизированный pytest-feedback** (VeriHarness, arXiv:2607.14167): сырой traceback
   заменяется структурой `{status, failed_tests[], error_types_found[]}` —
   на моделях 8–14B это дало +42–44pp.
2. **replace_in_file вместо генерации диффов**: малые модели стабильно ошибаются в
   формате unified diff; точечная замена с показом ближайшего контекста при промахе
   даёт модели самокоррекцию без `ModelRetry`.
3. **Фильтр-до-LLM** (OpenAnt, arXiv:2606.19149): workflow аудита предписывает grep по
   sink-паттернам (`execute(`, `eval(`, `pickle`, `jwt.decode`, ...) ДО чтения файлов —
   сокращение анализируемого кода на 96–99%.
4. **Чтение всех артефактов в форензике** (RAG-IR, arXiv:2603.18196): из-за сэмплирования
   терялось 3.6–4.3% решающих записей логов.
5. **Внешние оракулы** (Vul4Py + Self-Authored Verification): верифицируется только
   то, что нельзя «самоподтвердить»: JSON-валидность, формат key=value, зелёный pytest.
6. **Exploration budget** (CVE-Bench, arXiv:2503.17332): 67–80% отказов агентов —
   преждевременная остановка; workflow'ы требуют разведки перед выводами.
7. **Контекст-гигиена** (ACM, arXiv:2607.23809): усечение вывода инструментов до 7k
   символов с подсказкой «уточните через grep/read_file».

### Устойчивость к OpenAI-совместимым серверам

Критичная находка: pydantic-ai 1.44 падает `ValidationError` на ответах Groq —
поле `service_tier: "on_demand"` не входит в enum схемы `ChatCompletion`.
Решение — транспорт-обёртка `_NormalizeTransport` (httpx), вычищающая
`service_tier`, `x_groq`, `logprobs` из JSON-ответов до того, как их увидит SDK.
Это же защищает от любых серверов, добавляющих нестандартные поля.

### Бюджеты и rate limiting

- `SEC_AGENT_MAX_REQUESTS` (по умолчанию 45) — жёсткий лимит запросов на задачу
  (`UsageLimits`), с запасом под repair-фазу.
- `SEC_AGENT_TIME_BUDGET` (по умолчанию 540с) — wall-clock лимит; проверяется между фазами.
- `SEC_AGENT_RPM` — троттлинг на транспортном уровне (равномерный интервал между
  запросами), `SEC_AGENT_RPD_CAP` — дневной предохранитель.
- 429 разделяются на **per-minute** (OTPM/RPM: парсинг «try again in Xs» из тела,
  ожидание и retry внутри задачи) и **per-day** (TPD/RPD: fail-fast — ждать бессмысленно).
- Серийные запросы только; никакого параллелизма (RPM 30 мал, и малые модели
  деградируют на длинных промптах).

## Формат сабмита

```
submission.zip
├── run.sh          # входная точка: exec python3 sec_agent.py "<instruction>"
└── sec_agent.py    # весь агент, self-contained
```
