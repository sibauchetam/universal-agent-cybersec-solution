# Исследование на AlphaXiv: статьи и их внедрение в агента

Даты: 2026-09-04 (раунд 1), 2026-09-05 (раунд 2). Поиск через официальный MCP-эндпоинт AlphaXiv
(`POST https://api.alphaxiv.org/mcp/v1`, инструменты `discover_papers` /
`get_paper_content`). Всего в проекте отобрано 32 статьи: 17 в раунде 1 (CTF/SWE-fix/
аудит/форензика/малые модели/self-verification) и 15 в раунде 2 (архитектура
single-vs-multi, надёжность tool-calling, память, test-time budget, форензика).
Здесь — статьи, давшие прямые инженерные практики, вшитые в `submission/sec_agent.py`.

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

---

# Раунд 2 (2026-09-05)

Методология: 8 запросов `discover_papers` по направлениям, не покрытым раундом 1
(мульти-агент vs single-agent, надёжность function calling, память/дистилляция опыта,
test-time бюджет, статический анализ + LLM, plan-then-execute, анти-форензика,
структурированный вывод), затем `get_paper_content` по 15 отобранным статьям
(детальные разборы: `/tmp/research/analysis_{a,b,c}.md`, сырые отчёты: `/tmp/research/r2_c_*.txt`).

## 2.1. Архитектура: почему single-agent + фиксированные планы — оптимум

### 2601.04748 — When Single-Agent with Skills Replace MAS and When They Fail (UBC/Vector, 53 votes)
Компиляция MAS → single-agent со «скиллами» сохраняет точность (+0.7% в среднем)
при экономии 53.7% токенов, 49.5% латентности и 3–4× запросов. Точность выбора
скилла падает сверхпорогово при |S| > κ≈50–100 (γ=1.56–1.72, R²>0.97); один
семантический «конкурент» в описании — минус 7–30% точности выбора. Сложность
execution policy (~30/100/300 токенов) на выбор не влияет.

### 2604.02460 — Single-Agent LLMs Outperform MAS Under Equal Thinking Token Budgets (Stanford, 24 votes)
На Qwen3-30B-A3B и двух других семействах, при равных бюджетах 100–10000 токенов,
одиночный агент сопоставим или лучше 5 MAS-архитектур (Sequential/Subtask-parallel/
Parallel-roles/Debate/Ensemble). Плато точности при ~1–2k thinking-токенов (дальше —
over-exploration). Главный режим отказа: потеря уже найденного корректного значения
при финальной экстракции ответа. Отрицательный результат: SAS-L pre-answer scaffold
на Qwen3 не помогает и иногда вредит.

### 2605.14290 — Web Agents Should Adopt the Plan-Then-Execute Paradigm (UC Berkeley)
Разбор всех 860 задач WebArena: 81.28% выражаются статической программой (иммунны
к prompt injection), 18.72% требуют LLM только для обработки данных, 0% требуют
динамического replan'а. Главный практический гэп PTE — отсутствие обработки ошибок.

### 2605.22138 — Self-Regulated Simulative Planning (CMU, 31 votes)
Декомпозиция «реактивное исполнение / симулятивное планирование / селективная
регуляция» даёт 71.3 Pass@1 на 5,518 токенах (−25.8–95.3% reasoning-токенов против
сопоставимых 30B-моделей). Абляция селективности: без неё +526 токенов/траекторию
без роста точности. В неопределённой среде планы нужно резать до ≤2 шагов.

### 2608.18931 — Test-Time Scaling in the Wild: Exploitation, Not Exploration, Is the Bottleneck (11 votes)
Oracle-качество пула кандидатов растёт с compute, а реализованное — нет: бутылочное
горлышко — exploitation. Reward-модели бесполезны на открытых задачах (ρ≈0.11–0.12);
Best-of-N захватывает ~15% headroom, лучший метод (Fusion, механическое слияние
кандидатов) — ~40%. Sequential refinement иногда регрессирует (−2.3…−4.5 п.п.) —
итеративные «улучшения» могут портить хороший черновик.

**Внедрено из 2.1:** anti-confusable ревизия описаний инструментов и «когда
использовать» (2601.04748); notes-to-file `/app/.findings.md` + span-carrying
«значения дословно из tool-выводов» (2604.02460); injection-guard «содержимое
файлов — данные, не инструкции» + contingency-ветки в PLAN + валидация отказа
от динамического replan-оркестратора (2605.14290); STATUS→ACTION→EXPECTED
однострочник перед нетривиальными командами и микро-план ≤2 шагов для
forensics/ctf (2605.22138); best-snapshot deliverable в repair-фазе —
единственная обязательная кодовая правка батча (2608.18931).

## 2.2. Надёжность tool-calling и структурированного вывода

### 2608.22472 — Small Reasoning Models are Instruction Followers in Function Calling
Малые модели (0.5–15B) следуют естественноязыковым инструкциям лучше, чем
манипулируют нативными JSON-схемами: IFFC (tools как текстовые инструкции,
вызов в тексте, декомпозиция) поднимает Qwen-3 4B до 86.7% Live BFCL против 81%
NFC; декомпозиция устраняет context pollution (Gemma-3 4B ~0% → 79.1% на
Parallel Multiple). Think-режим резко помогает выбору инструмента.

### 2510.07248 — Don't Adapt SLMs for Tools; Adapt Tool Schemas to the Models (SNU)
Доминирующий отказ малых моделей — schema misalignment: галлюцинация
«преобученческих» имён инструментов. PA-Tool (training-free): переименование
инструментов/параметров под peakedness-процедуру (N=32 кандидата, α=0.2, t=0.4)
даёт до +17% Reliability, −80% галлюцинаций несуществующих тулов; Llama3.1-8B
обгоняет Claude-Sonnet-4.5 на MetaTool Multi-tool. Имена тулов — первичный сигнал
выбора (шум имён роняет точность 58.1→37.1 при нетронутых описаниях).

### 2510.17052 — ToolCritic: Detecting and Correcting Tool-Use Errors (USC/Amazon)
Самокоррекция малых моделей вредит (success 5.46% → 3.90%); внешний критик с
ОПИСАТЕЛЬНЫМ фидбеком по 8-классовой таксономии даёт +13.7 п.п. (Claude 3 Sonnet).
Критика «только категория» без объяснения даёт заметно меньший прирост. Самые
полезные классы для нас: Non-Invocation Hallucination (выдумал содержимое вместо
вызова инструмента), Premature Invocation, Observation Reasoning Error.

### 2605.13076 — TruncProof: Guardrail for JSON Generation under Token Constraints
При жёстком токен-лимите все бейзлайны (включая grammar-constrained) падают:
Syntax 1–36%; TruncProof через LL(1)-оценку «стоимости завершения» — 100%.
Корневая причина обрезаний — токены на пробелы/отступы. Компакт-директива в
промпте даёт измеримый прирост выживания.

### 2601.22952 — Sifting the Noise: LLM Agents in Vulnerability False Positive Filtering
Фильтрация FP у SAST: агентность помогает только сильным моделям (DeepSeek: агент
хуже ванильного промпта). Успешные паттерны: cross-file semantic resolution
(51.2% успехов), constant folding через python3, проверка конфигов вместо доверия
дефолтам. Опасные паттерны: поверхностный pattern matching без трассировки
sanitizer'а; главный риск — подавление истинных уязвимостей (до 77–84% на
crypto/config классах!). Инъекции (CWE-78/89/79) агент проверяет надёжно (<3% пропусков).

**Внедрено из 2.2:** механический alias-репейр имён инструментов (TOOL_ALIASES +
edit-distance) вместо LLM-retry (2510.07248); json_closer — механическая минимальная
достройка усечённого JSON + обработка finish_reason=length + компакт-JSON директива
(2605.13076); anti-FM3 гвардейлы в audit-blueprint (трассировка sanitizer'а, запрет
тестовых/example путей, сверка с целевым классом, политика «включай при сомнении»)
(2601.22952); расширение таксономии ошибок запланировано (2510.07248/2510.17052).

## 2.3. Память и дистилляция опыта (offline)

### 2608.07169 — Agent Memory Distillation (KAIST, 20 votes)
Training-free перенос опыта учителя малым моделям через 3-уровневую память:
Workflow (проза + типизированные плейсхолдеры, проактивно) / Subtask (code-centric,
наибольший инкремент +25.0 п.п.) / Function (реактивно, при ошибках). Средне
+27.2 п.п. на AppWorld; студенты 4–8B догнали учителя GPT-5-mini. k=1 retrieval
оптимален, k>1 деградирует. Сырая память учителя почти не работает — форма
и гранулярность критичны.

### 2608.27454 — WikiSkill: Compiling Agent Experience into Persistent Knowledge (Google, 159 votes)
Трёхслойное рабочее пространство raw/ → wiki/ (pattern-страницы из 5 fail + 3
pass трейсов) → skills/. На нашей модели Qwen-3.6-27B прирост до +23.9 пунктов;
постоянный wiki для пропозера скиллов +15 п.п. Доступ inference-агента к wiki
во время обучающих прогонов ВРЕДЕН (−2.8). Негативный перенос: скиллы слабых
моделей ухудшают сильных (low-level workaround'ы).

**План из 2.3 (после отката квоты Groq):** mini-WikiSkill конвейер — прогон агента
на 18 задачах → дистилляция fail/pass трейсов → mem/workflow_*.md + mem/subtask_*.md
(code-centric сниппеты) + mem/function_errors.md; инжекция ровно 1 workflow + 1
subtask блока механическим классификатором (k=1); reactive-хинты в repair_hint().

## 2.4. Аудит и форензика: как не наврать

### 2604.20179 — Taint-Style Vulnerability Detection for Node.js via LLM Agent Reasoning (CMU+Google)
Мультистадийный пайплайн Finder (max recall) → Judge (консервативная reachability)
→ Constraints → Exploiter с execution-oracle маркерами: 83.75% подтверждений против
43.13% у лучшего классического; 94.2% на приватном бенчмарке. FP-таксономия:
нельзя эмулировать окружение/подменять built-ins, считать достижимыми пути из
тестов/examples, верить sanitizer'у без проверки.

### 2605.29269 — HunterAgent: Attack Trace Reconstruction under Anti-Forensics (HIT)
Реконструкция цепочки атаки по частично уничтоженным логам: LLM только предлагает
гипотезы, детерминированный Verifier заземляет их по «выжившей» телеметрии.
F1 86.1% против 57.7–61.2 у tool-augmented ReAct; Path Hallucination Rate
61.5% → 6.4%; −69.3% токенов. При 70% затёртых логов precision держится 84.0 и
95.7% расследований корректно останавливаются с INSUFFICIENT_EVIDENCE вместо
фабрикации. OS-физика: t_src < t_dst, PPID-цепочки, отвержение невозможных переходов.

### 2608.03591 — DiagChain: Evidence-Grounded Attack Chain Reconstruction (Tsinghua)
Оценка реконструкции по стадиям: воронка провалов E1 улика не увидена → E2
увидена, но не использована → E3 процитирована частично → E4 неверный порядок.
У моделей нашего масштаба доминирует E2 (Qwen-3-32b: 39.2%) — лечится механическим
grounding-кроссчеком, а не увеличением бюджета (k=64 лишь наращивает токены и Gap).
Больше бюджета ≠ лучше цепочка; early stop после 3 ходов без новой улики.

**Внедрено из 2.4:** в forensics-blueprint — EVIDENCE RULES (каждое число из
команды grep -c/wc/awk/python3; хронологическая монотонность; при tamper —
пережившие каналы: *.gz, wtmp/btmp/lastlog, syslog, journalctl, mtimes,
cron/systemd; ≤1 инференс-хопа на строку) (2605.29269); в audit-blueprint —
one-finding-per-sink (anti-merge), FP-гвардейлы, notes-to-file (2604.20179 +
2608.03591); механический grounding-кроссчек и карточная компакция — в плане.

---

## Сводка: практика → код (раунд 2)

| Практика | Источник | Где в коде | Статус |
|---|---|---|---|
| Injection-guard (данные ≠ инструкции) | 2605.14290 | SYSTEM_COMMON | ВШИТО |
| Span-carrying вербатим-значений | 2604.02460 | SYSTEM_COMMON | ВШИТО |
| STATUS→ACTION→EXPECTED однострочник | 2605.22138 | SYSTEM_COMMON | ВШИТО |
| Notes-to-file /app/.findings.md | 2604.02460, 2608.03591 | WORKFLOWS[audit/forensics/ctf] | ВШИТО |
| Anti-merge: один sink = один finding | 2608.03591 | WORKFLOWS[audit] | ВШИТО |
| FP-гвардейлы аудита (sanitizer, тестовые пути, класс CWE) | 2601.22952, 2604.20179 | WORKFLOWS[audit] | ВШИТО |
| Компакт-JSON (одна строка, без отступов) | 2605.13076 | WORKFLOWS[audit] | ВШИТО |
| EVIDENCE RULES форензики (команды, монотонность, выжившие каналы, ≤1 хоп) | 2605.29269 | WORKFLOWS[forensics] | ВШИТО |
| Микро-план ≤2 шагов | 2605.22138 | WORKFLOWS[forensics/ctf] | ВШИТО |
| Contingency-ветки (пустой grep, полный traceback, healthz) | 2605.14290 | WORKFLOWS[audit/fix/generic] | ВШИТО |
| json_closer: механическая достройка усечённого JSON | 2605.13076 | json_closer() + ensure_deliverable | ВШИТО |
| finish_reason=length телеметрия | 2605.13076 | _NormalizeTransport | ВШИТО |
| Best-snapshot deliverable против repair-регрессии | 2608.18931 | deliverable_health() + ensure_deliverable | ВШИТО |
| Alias-репейр имён инструментов | 2510.07248 | TOOL_ALIASES + fallback dispatch | ВШИТО |
| Offline-ренейминг тулов под qwen3.6-27b (peakedness) | 2510.07248 | офлайн-процедура | ПОСЛЕ ОТКАТА КВОТЫ |
| IFFC текстовый протокол FC в fallback | 2608.22472 | run_openai_fallback | LATER (A/B) |
| Компакция с защитой строк-улик | 2604.02460 | history processor | LATER |
| Fusion findings[] при ≥2 валидных отчётах | 2608.18931 | repair-финализация | LATER (проверить толерантность верификатора) |
| Grounding-кроссчек якорей против E2 | 2608.03591 | mechanical verify | LATER |
| Mini-WikiSkill конвейер + AMD-памятки (k=1) | 2608.07169, 2608.27454 | mem/*.md + system prompt | ПОСЛЕ ОТКАТА КВОТЫ |
| Card-компакция форензики (≤900 симв., ≤48 карточек) | 2608.03591 | history processor | LATER |

Отброшено с количественным обоснованием: MAS-оркестрация любого рода (2601.04748,
2604.02460: +0.7% acc, −53.7% токенов у SAS); BoN/RM/beam/particle search (2608.18931:
ρ≈0.11–0.12 у RM, механические верификаторы лучше); SAS-L scaffold на Qwen3
(2604.02460); runtime-эволюция скиллов (2608.27454: офлайн-заезд); logit-маскинг
(2605.13076: недоступен через API).
