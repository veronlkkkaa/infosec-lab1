# infosec-lab1

Лабораторная работа № 1: защищённый REST API журнала инцидентов информационной безопасности.
Пользователь входит по логину и паролю, получает JWT, создаёт свои инциденты,
просматривает их и меняет статус.

**Автор:** Гаврилович Вероника Вячеславовна, Р3431.

**Репозиторий:** [veronlkkkaa/infosec-lab1](https://github.com/veronlkkkaa/infosec-lab1).

За основу организации кода и CI взят
[cysec_1, версия 20227df](https://github.com/zazhigalka56123/cysec_1/tree/20227dfc86d92b264d5cbfe2bb7b2b034f3070c4).
Здесь реализована своя предметная область — инциденты ИБ, файловая база и два пользователя
для проверки разграничения доступа.

## Стек и структура

Spring Boot 4.1.2, Kotlin, Java 21, Spring MVC, Spring Security, Nimbus JWT,
Spring JDBC / JdbcTemplate, H2, Jackson 3. Gradle Wrapper 8.14.5.
Пароли: BCrypt с cost 12. Тесты: JUnit и MockMvc.

Компилятор и Spring-плагин Kotlin закреплены на 2.4.20 — в пределах
[заявленной поддержки CodeQL](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/).
Runtime-библиотеки Kotlin управляются BOM 2.4.21. Версии Spring-зависимостей задаёт Spring Boot BOM.

Исходники находятся в `src/main/kotlin/ru/itmo/infosec/lab1/`:

| Пакет | Назначение |
|---|---|
| auth | AuthController, AuthService, создание пользователей, BCrypt, хранилище пользователей и DTO входа |
| incident | IncidentController, сервис, репозиторий, DTO, категории и статусы инцидентов |
| security | SecurityConfig, JwtConfig, ограничение входов и размера запросов |
| error | Единые JSON-ошибки и обработка исключений |
| validation | Проверка текста и ограничения BCrypt |
| config | Строгая обработка JSON |

Контроллер принимает HTTP-запрос, сервис проверяет правила, репозиторий выполняет SQL.
Объекты запросов и ответов отделены от модели хранения.

## Запуск

Нужны JDK 21, OpenSSL; для скрипта входа также нужен jq.
На этом Mac JDK 21 можно выбрать так:

```bash
export JAVA_HOME="/Users/mr-bombastic/Library/Java/JavaVirtualMachines/arcadia-jdk-21"
./scripts/run-local.sh
```

Команды выполняются из корня проекта. Скрипт скрыто запрашивает пароли alice и bob
и генерирует ключ JWT, если он ещё не задан. Для новых пользователей пароль должен содержать
минимум 15 символов и занимать не более 72 байт UTF-8. Готовых паролей в проекте нет.

Сервис слушает `http://127.0.0.1:8080`.
По умолчанию данные сохраняются в `data/incident-log.mv.db`.
Путь можно изменить через DATABASE_URL. Для уже созданной в ходе демонстрации базы:

```bash
DATABASE_URL="jdbc:h2:file:./data/demo-20261026-202536" ./scripts/run-local.sh
```

Повторный запуск с той же базой сохраняет пользователей и инциденты.
Ввод другого начального пароля не меняет пароль существующего пользователя.
После перезапуска с новым ключом JWT необходимо повторить вход.

## API

Тела запросов и ответов передаются в JSON.
Защищённым методам нужен заголовок `Authorization: Bearer <token>`.

| Метод | Ручка | Тело запроса | Успех | Доступ |
|---|---|---|---|---|
| POST | /auth/login | username, password | 200: access_token, token_type, expires_in | Без токена |
| GET | /api/data | — | 200: items, до 100 своих инцидентов | JWT |
| POST | /api/incidents | title, description, category, severity | 201: созданный инцидент | JWT |
| PATCH | /api/incidents/{id}/status | status | 200: обновлённый инцидент | JWT |

- title — непустая строка до 120 UTF-16 единиц, description — до 2000.
- category: PHISHING, MALWARE, UNAUTHORIZED_ACCESS, DATA_LEAK, OTHER.
- severity: LOW, MEDIUM, HIGH, CRITICAL.
- Статусы: NEW → IN_PROGRESS → CLOSED. Пропуск и обратный переход запрещены.
- Повтор текущего статуса разрешён, время изменения остаётся прежним.

Ответ инцидента содержит id, title, description, category, severity, status, created_at, updated_at.
Список имеет вид `{"items":[...]}`; при отсутствии записей — `{"items":[]}`.

### Пример запросов

В отдельном терминале проекта:

```bash
# Вход: скрипт скрыто запросит пароль.
TOKEN="$(./scripts/login.sh alice)"

# Список своих инцидентов.
curl -i http://127.0.0.1:8080/api/data \
  -H "Authorization: Bearer $TOKEN"

# Создание с сохранением ID из ответа.
INCIDENT_ID="$(curl --fail-with-body -sS http://127.0.0.1:8080/api/incidents \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"title":"Подозрительное письмо","description":"Ссылка на поддельную страницу входа","category":"PHISHING","severity":"HIGH"}' \
  | jq -er '.id')"

# Перевод в работу.
curl -i -X PATCH "http://127.0.0.1:8080/api/incidents/$INCIDENT_ID/status" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"status":"IN_PROGRESS"}'

# Закрытие.
curl -i -X PATCH "http://127.0.0.1:8080/api/incidents/$INCIDENT_ID/status" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"status":"CLOSED"}'
```

В Postman используются те же адреса и тела: для входа выбрать POST /auth/login,
Body → raw → JSON и ввести свой логин и пароль. Полученный access_token указать
в Authorization → Bearer Token для запросов /api/*. Заголовок Content-Type — application/json.

Открытие адреса API в обычной вкладке браузера не добавляет Bearer-заголовок и возвращает 401.
Отдельного пользовательского сайта у приложения нет.

### Проверки для защиты

| Действие | Ожидаемый результат |
|---|---|
| GET /api/data без JWT | 401 |
| Вход с неверным паролем или несуществующим логином | Одинаковый ответ 401 |
| Создание инцидента alice | 201, статус NEW |
| Вход как bob и получение списка | Запись alice отсутствует |
| Попытка bob изменить ID записи alice | 404 |
| Переход NEW сразу в CLOSED | 409 |
| Логин с SQL-фрагментом: alice' OR 1=1 -- | 401 |
| Описание со строкой &lt;script&gt;alert(1)&lt;/script&gt; | Ответ содержит экранированный текст |
| Лишнее поле owner_id или число вместо severity | 400 |

Ошибки имеют формат `{"error":"код"}`.
Используются 400 invalid_request, 401 unauthorized, 403 forbidden, 404 not_found,
409 invalid_status_transition / incident_changed, 413 request_too_large,
415 json_required, 429 too_many_requests.

## Меры защиты

### SQL-инъекции

UserRepository и IncidentRepository передают значения через параметры `?` в JdbcTemplate
и PreparedStatement. Например, поиск пользователя использует `WHERE username = ?`,
а обновление инцидента — `WHERE id = ? AND owner_id = ? AND status = ?`.

SQL фиксирован. Пользовательская строка передаётся как значение параметра, а не приклеивается
к тексту запроса. Кавычки и SQL-команды внутри введённого текста не меняют структуру запроса.
Проверка длины и формата дополняет параметризацию.

### XSS

IncidentController.toResponse вызывает `HtmlUtils.htmlEscape(..., "UTF-8")` для title и description.
Обработка применяется к созданию, списку и обновлению статуса.
В базе хранится исходный текст, при выдаче он экранируется один раз:
`<script>alert(1)</script>` превращается в `&lt;script&gt;alert(1)&lt;/script&gt;`.

Ответы имеют Content-Type application/json. Spring Security задаёт
X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'.
HTML-экранирование предназначено для текстового HTML-контекста и не заменяет безопасный
вывод внутри JavaScript, CSS или URL.

### Пароли и вход

BootstrapUsers сохраняет только BCrypt-хэш с cost 12. BCrypt создаёт случайную соль;
в строке хэша сохраняются параметры алгоритма, соль и результат.
AuthService проверяет пароль через PasswordEncoder.matches, а не расшифровывает его.
Для неизвестного пользователя тоже выполняется проверка хэша.

LoginRequest и UserRecord — обычные классы без сгенерированного toString с паролем или хэшем.
Пароли не записываются в исходники и сообщения ошибок.
Граница 72 байта предотвращает неоднозначную проверку обрезанного BCrypt-пароля.

### JWT и авторизация

AuthService выдаёт JWT на 15 минут с подписью HS256. Пароль и его хэш в JWT не входят.
JwtConfig проверяет подпись, issuer, audience, обязательные временные поля и наличие пользователя.
Ключ JWT_SECRET_BASE64 задаётся через окружение и должен содержать минимум 32 случайных байта.

SecurityConfig разрешает публично только POST /auth/login, а три метода работы с инцидентами
требуют JWT. Остальные маршруты запрещены. Cookie-аутентификация, HTTP Basic и серверные сессии
отключены; токен передаётся явно в Bearer-заголовке. Для такой схемы CSRF отключён.

Владелец определяется по проверенному sub из JWT. Запросы к базе ограничены owner_id.
Чужой и несуществующий ID дают одинаковый 404. Смена статуса выполняется в транзакции;
условие по прежнему статусу предотвращает перезапись конкурентного изменения.

JWT подписан, но не зашифрован. Для доступа вне localhost нужен HTTPS.
Refresh token, MFA и индивидуального отзыва токена в этой работе нет.

### Валидация и ограничения

Bean Validation и TextRules проверяют обязательные поля, длины, Unicode и отсутствие NUL.
JsonConfig запрещает неявное преобразование чисел и boolean в строки и enum.
Неизвестные поля и лишний JSON отклоняются.

RequestGuardFilter ограничивает тело запроса 16 КиБ, в том числе при chunked-передаче.
LoginLimiter разрешает не более 10 попыток входа за минуту с одного IP.
Ошибки возвращаются без stack trace, SQL-параметров, паролей и токенов.
Ответы защищённых методов не кэшируются.

## CI и отчёты SAST/SCA

[GitHub Actions](https://github.com/veronlkkkaa/infosec-lab1/actions) запускается при push,
pull request и вручную. Workflow: [.github/workflows/ci.yml](.github/workflows/ci.yml).

| Job | Что делает | Артефакт |
|---|---|---|
| api-tests | Сборка и интеграционные тесты API и безопасности | api-tests: HTML и JUnit XML |
| sast | CodeQL для java-kotlin, набор security-extended | codeql-sast: SARIF |
| sca | OWASP Dependency-Check 12.2.2, прямые и транзитивные runtime-зависимости | dependency-check-sca: HTML и JSON |

### SAST

CodeQL собирает Kotlin-код в manual-режиме с отключённым build cache и компиляцией in-process,
чтобы анализатор видел компиляцию. Результаты отправляются в Security → Code scanning
и сохраняются в артефакте codeql-sast.

Скрипт [scripts/check-codeql.py](scripts/check-codeql.py) завершает job ошибкой при находках,
отсутствии или некорректном отчёте. Единственное рассмотренное исключение —
java/spring-disabled-csrf-protection на конкретной строке SecurityConfig:
API использует явный Bearer-заголовок без cookie и сессий.
Правило, путь и строка закреплены в скрипте; изменение строки требует повторного рассмотрения.
Исключение отображается в сводке CI, исходный SARIF сохраняется без удаления находки.

### SCA

Анализируется полный разрешённый runtimeClasspath: прямые зависимости и библиотеки,
которые они подтягивают. Тестовые зависимости, Gradle-плагины и JDK не входят в этот набор.
Дополнительная проверка SHA-256 требует присутствия каждого runtime JAR в JSON-отчёте.
CVSS ≥ 7 или ошибка анализатора приводят к падению job.

Используется штатный NVD API. Версия Dependency-Check 12.2.2 сохранена из-за
[ошибки анонимного доступа в 13.0.0](https://github.com/dependency-check/DependencyCheck/issues/8715).
NVD_API_KEY передаётся из одноимённого repository secret; пустое значение не устанавливается.
Ключ пользователь добавляет в
[Settings → Secrets and variables → Actions](https://github.com/veronlkkkaa/infosec-lab1/settings/secrets/actions).
Значение ключа не нужно присылать в чат или добавлять в Git. OSS Index отключён.

База NVD находится в .cache/dependency-check и исключена из Git.
В CI её восстановление, обновление и анализ показаны отдельными шагами.
После успешного обновления база сохраняется до анализа: находка уязвимости не лишает следующий
запуск кэша. Ошибки обновления не скрываются, сканирование с неполной базой не засчитывается.
Первый полный импорт может быть долгим; кэш сокращает повторные загрузки.
SCA jobs репозитория выполняются последовательно, вывод --info показывает прогресс.

### Где взять отчёты и скриншоты

Открыть Actions → нужный запуск → Artifacts:

- api-tests — скачать ZIP и открыть index.html.
- codeql-sast — скачать SARIF; находки также доступны в Security → Code scanning.
- dependency-check-sca — скачать ZIP и открыть dependency-check-report.html.

Для актуальной версии нужно сохранить в docs/screenshots/:

- codeql-report.png — результат SAST и сводку находок из соответствующего запуска.
- sca-report.png — сводку HTML-отчёта SCA.
- ci-summary.png — страницу запуска с коммитом и итогом трёх jobs.

Эти скриншоты добавляются после фактического завершения новых проверок.
Наличие конфигурации CI само по себе не подтверждает прохождение анализа.

Архивный скриншот SpotBugs относится к
[запуску № 1, коммит 70880fa](https://github.com/veronlkkkaa/infosec-lab1/actions/runs/40358417953).
Он не является результатом CodeQL или проверкой текущей структуры проекта:

![Архивный отчёт SpotBugs: 39 классов, 0 предупреждений](docs/screenshots/sast-report.png)

Оригинальные старые отчёты сохранены в docs/evidence/ci-40358417953/.
