# Исследование на AlphaXiv: статьи и их внедрение в агента

Дата: 2026-09-05. Поиск через официальный MCP-эндпоинт AlphaXiv
(`POST https://api.alphaxiv.org/mcp/v1`, инструменты `discover_papers` /
`get_paper_content`). Всего в проекте отобрано 17 статей; здесь — три, которые
дали прямые инженерные практики, уже вшитые в `submission/sec_agent.py`.

---

## 1. arXiv 2506.08669 — Enhancing Reasoning Capabilities of Small Language
### Models with Blueprints and Prompt Template Search (Han et al., Microsoft)

**Суть.** Малые модели (SLM) слабо рассуждают и крайне чувствительны к формату
промпта. Авторы предлагают training-free подход: сильная LLM генерирует
«blueprint» — переиспользуемый пошаговый план решения для *класса* задач —
в нескольких стилях (`bullet-points`, `decision-making`, `concrete-example` и
др.), доводит его APO-циклом по ошибкам модели, а затем поиск по 32 шаблонам
промпта (число примеров, порядок блоков, blueprint on/off, CoT on/off) методом
successive halving выбирает оптимальную компоновку. На инференсе blueprint
просто подставляется в промпт — никаких дообучений.

**Ключевые цифры.** Mistral-7B +20% на MBP против CoT (3-shot); Phi-3-mini
+5.7% на BBH; связка «blueprint + template search» лучшая в 5 из 9 пар
модель/датасет. Качественный разбор (Fig. 4): с blueprint модель дословно
следует шагам («Define the Goal → Break Down the Information → Clarify
Criteria → Step-by-Step»), без него — хаотично прыгает в детали и ошибается.

**Что внедрено.** WORKFLOWS агента перестроены из плоских списков шагов в
структуру blueprint'а: `GOAL → INFORMATION → DECISION CRITERIA → PLAN`.
Пять категорий задач (audit / fix / forensics / ctf / generic) = пять
категорийных blueprint'ов, выбираемых механическим классификатором — это
ровно «offline-фаза» статьи: blueprint'ы сгенерированы заранее и вшиты в код,
потому что на конкуренции интернета нет. Компактность ограничена (~150 слов,
unit-тест `test_blueprints_have_paper_structure`), т.к. blueprint едет в
каждом системном промпте. Template search в offline-ВМ недоступен, но
компоновка «blueprint в system prompt, инструкция — в first message»
соответствует лучшим вариантам из статьи.

## 2. arXiv 2604.25039 — Dual-Track CoT: Budget-Aware Stepwise Guidance for
### Small LMs

**Суть.** Пара «Decomposer–Evaluator»: один агент предлагает следующий шаг в
жёстком формате (`STEP:` / `FINAL ANSWER:`), второй оценивает его по шкале
0–3 и возвращает короткий хинт. Глобальный токен-бюджет ограничивает диалог.
Главная инженерная находка — **rejection cache**: перед вызовом Evaluator
шаг нормализуется в «fingerprint» (только числа и операторы); если шаг
повторяет уже принятый или почти совпадает с ранее забракованным, он
отвергается **механически, без запроса к модели**.

**Что внедрено.** Прямой аналог — `repetition_guard()` в `sec_agent.py`:
каждый вызов инструмента (bash / read_file / grep / list_dir / run_pytest)
фингерпринтится парой `(инструмент, нормализованные аргументы)` и хэшем
вывода. Третье подряд идентичное срабатывание → в контекст модели вместо
молчаливого повтора инжектится механическая инструкция «ты в петле: смени
подход / сначала отредактируй файлы / пиши deliverable», а после трёх
strikes — жёсткое «STOP exploring, пиши ответ». Легитимные повторы
(перечитал файл после правки → вывод изменился) проходят свободно, потому
что хэш вывода другой. Это экономит LLM-ходы — критично при наших лимитах
Groq (OTPM 1000, RPM 30) и не тратит токены на «обнаружение петли» моделью.

## 3. arXiv 2607.05199 — Reason, Reward, Refine: Step-Level Error Correction
### with Structured Feedback for SLMs

**Суть.** Ошибки малых моделей в многошаговом выводе делятся на таксономию:
Miscomprehension (неверно понял задачу), Conceptual Misapplication (верный
принцип — неверное применение), Calculation Error (арифметика/подсчёт).
Структурированный фидбек по *типу* ошибки (а не сырой текст ошибки) даёт
до +27pp точности на hard-бенчмарках (LLaMA-3.2-3B: 30.2% → 57.3% на
JEEBench против CoT) и снижает Calculation Errors до −33.4%.

**Что внедрено.** Механическая **атрибуция ошибок** в repair-фазе:
`verify_deliverable()` возвращает машиночитаемую причину, `attribute_error()`
классифицирует её в `missing | format | content`, и `repair_hint()` выдаёт
адресную подсказку под класс (для format — точный формат deliverable по
категории, для content — требование пересчитать значения механически через
python3/awk, для missing — немедленно создать файл). CRITIC-промпт дополнен
трёхклассовой атрибуцией перед исправлением. Это тот же принцип «typed
feedback», что уже дал прирост в `parse_pytest_feedback` (+42pp по данным
статьи о structured feedback), распространённый на весь repair-путь.

---

## Сводка: статья → код

| Статья | Практика | Где в коде |
|---|---|---|
| 2506.08669 | Категорийные blueprint'ы GOAL/INFO/CRITERIA/PLAN | `WORKFLOWS`, `build_system_prompt` |
| 2506.08669 | Компактность промпта, офлайн-фаза генерации | unit-тест длины; генерация вне ВМ |
| 2604.25039 | Rejection cache по fingerprint'ам | `repetition_guard`, `AgentState.call_history` |
| 2604.25039 | Жёсткий бюджет на интеракцию | `MAX_REQUESTS`, `UsageLimits(request_limit)` |
| 2607.05199 | Таксономия ошибок + типизированный фидбек | `attribute_error`, `repair_hint`, CRITIC |
| 2607.05199 | Механический пересчёт вместо «прикидки» | PLAN-шаги forensics/audit |

## Остальные статьи пулла (использованы ранее)

- 2408.08926 (Cybench), 2503.17332 (CVE-Bench), 2508.05674 (CTF-гиперпараметры):
  декомпозиция сложных CTF, fast-path для тривиальных задач.
- 2607.29422 (AgenticRepair), 2607.00990 (SWE-Doctor), 2608.00692 (Vul4Py):
  двойная верификация PoC+pytest, минимальные патчи.
- 2512.07533 (VulnLLM-R), 2606.10281 (AuditBench): grep-фильтрация кандидатов
  до LLM (96–99% экономии анализа), signal-matching отчётов.
- 2603.18196 (RAG incident analysis): корреляция идентичностей между
  источниками логов — легла в blueprint forensics.
- 2606.19149 (OpenAnt), 2605.29676 (Notation Matters), 2607.23809 (context
  management), 2607.14167 (VeriHarness), 2607.24300 (self-authored verification
  unreliable): внешние оракулы вместо самооценки, компакция истории.
