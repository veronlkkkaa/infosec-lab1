# infosec-lab1

Журнал инцидентов информационной безопасности

Лабораторная работа № 1: защищённый REST API с интеграцией в CI/CD.
**Kotlin + Spring Boot.** Пользователь регистрирует инциденты, указывает категорию и
критичность, берёт их в работу и закрывает. Каждому доступны только собственные записи.

**Автор:** Гаврилович Вероника Вячеславовна, Р3431.
**Репозиторий:** [veronlkkkaa/infosec-lab1](https://github.com/veronlkkkaa/infosec-lab1).

**Статус на 26.10.2026:** новая версия подготовлена, но сборка, тесты, HTTP, SAST и SCA
после смены темы **не запускались**. 26 тестовых сценариев написаны, их результат неизвестен.
Предыдущие успешные результаты по заметкам хранятся отдельно и не подтверждают эту версию.
Старые PDF и ZIP вне папки проекта относятся к прежней версии и требуют обновления перед сдачей.

## Стек

Kotlin 2.4.21, Spring Boot 4.1.2, Spring MVC, Spring Security, Nimbus JWT,
Spring JDBC / JdbcTemplate, файловая H2. JDK 21, Gradle Wrapper 8.14.5.
Пароли: BCrypt, cost 12. JSON: Jackson 3. Тесты: JUnit / MockMvc.
SAST: SpotBugs 4.10.4 + Find Security Bugs 1.14.0. SCA: OWASP Dependency-Check 13.0.0.

Зависимости при смене темы не обновлялись. Их прежняя проверка датирована 25.10.2026;
новый запуск анализа ещё нужен. Gradle lock-файла пока нет.

## Открытие и запуск

В IntelliJ IDEA: File → Open → папка lab1-secure-api. Project SDK и Gradle JVM: JDK 21.
В VS Code: File → Open Folder → та же папка. Исходники находятся в src/main/kotlin/ru/itmo/infosec/lab1.
EditorConfig задаёт UTF-8, LF, четыре пробела и явные Kotlin-импорты.
Импорт Gradle в IDE может загрузить зависимости; это не подтверждение успешной сборки.

Для самостоятельного запуска на macOS/Linux нужны JDK 21 и интернет при первом скачивании зависимостей:

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 21)"
./scripts/run-local.sh
```

Скрипт запускает Gradle bootRun, то есть компилирует и запускает приложение.
Он скрыто запросит пароли учебных аккаунтов alice/bob: минимум 15 символов, максимум
72 байта UTF-8. Существующие пользователи не перезаписываются при повторном старте.
Если JWT_SECRET_BASE64 не задан, скрипт создаёт случайный ключ; старые токены после
смены ключа недействительны. Постоянный ключ не следует сохранять в Git.

API: http://127.0.0.1:8080. Новая база: data/incident-log.mv.db.
Старый файл data/lab.mv.db с заметками не удаляется и не преобразуется в инциденты.
Для новой базы первоначальные пользователи создаются заново.
DATABASE_URL, DATABASE_USERNAME и DATABASE_PASSWORD переопределяют настройки H2.
Файл .env.example содержит только памятку; автоматической загрузки .env нет.
Веб-консоль и TCP-сервер H2 выключены. Для внешнего доступа нужен HTTPS.
Старый JAR из build/libs не демонстрирует новую версию: перед демонстрацией нужна новая сборка.

## Архитектура

- ApiController: маршруты, получение владельца из JWT, формирование и экранирование ответов.
- IncidentService: создание, проверка владельца, переходы статуса и границы транзакций.
- IncidentRepository: параметризованный SQL, выборка своих записей, условное изменение статуса.
- IncidentApiModels: входные и выходные DTO; IncidentModels: внутренние модели и типы ошибок.
- AuthService / UserRepository: проверка пароля, выдача JWT и работа с пользователями.
- SecurityConfig / RequestGuardFilter / JsonConfig: JWT, лимиты и строгий JSON.
- ApiExceptionHandler: перевод ошибок сервиса в HTTP и единый JSON без паролей и SQL-параметров.

Таблица app_user хранит id, username, password_hash.
Таблица incident: id, owner_id, title, description, category, severity, status,
created_at, updated_at. Есть внешний ключ владельца, индекс (owner_id, id),
NOT NULL и CHECK для перечислений. Поля времени и начальный статус задаёт сервер.

## API

| Метод | Вход | Успех |
|---|---|---|
| POST /auth/login | username, password | 200: access_token, token_type, expires_in |
| GET /api/data | нет | 200: items, последние 100 своих инцидентов |
| POST /api/incidents | title, description, category, severity | 201: инцидент со статусом NEW |
| PATCH /api/incidents/{id}/status | status | 200: обновлённый инцидент |

Первые три метода покрывают обязательный контракт работы; PATCH добавляет обработку инцидента.
Все /api/* требуют Authorization: Bearer <token>. Маршрут заметок удалён.

- title: непустой текст до 120 UTF-16 единиц; description: непустой текст до 2000.
- category: PHISHING, MALWARE, UNAUTHORIZED_ACCESS, DATA_LEAK, OTHER.
- severity: LOW, MEDIUM, HIGH, CRITICAL.
- status: NEW → IN_PROGRESS → CLOSED. Пропуск, обратный переход и повторное открытие запрещены.
- Повтор текущего статуса разрешён и не меняет updated_at.

Значения перечислений передаются строками в верхнем регистре, не числами.
Создание не принимает status, owner_id, id и даты; неизвестные поля отклоняются.
Владелец определяется только из проверенного JWT. Чужой и отсутствующий ID одинаково дают 404.
При конкурентном изменении UPDATE сравнивает прежний статус: потерянная гонка даёт 409 incident_changed.

Ошибки: 400 invalid_request; 401 unauthorized; 403 forbidden; 404 not_found;
409 invalid_status_transition / incident_changed; 413 request_too_large;
415 json_required; 429 too_many_requests. Формат: {"error":"код"}.

## Демонстрация через curl

Ниже ожидаемое поведение для проверки после запуска, а не результаты выполненного прогона.
Сервер работает в первом терминале, команды выполняются во втором. Нужны curl и jq.

### Вход и регистрация события

```bash
curl -i http://127.0.0.1:8080/api/data
TOKEN="$(./scripts/login.sh alice)"
INCIDENT_ID="$(curl --fail-with-body -sS http://127.0.0.1:8080/api/incidents \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"title":"Подозрительное письмо","description":"Неожиданное вложение от неизвестного отправителя","category":"PHISHING","severity":"HIGH"}' \
  | jq -er '.id')"
curl -i http://127.0.0.1:8080/api/data -H "Authorization: Bearer $TOKEN"
```

Ожидается: 401 без токена; после входа 201 при создании и 200 при чтении. Статус новой записи - NEW.
login.sh запрашивает пароль скрыто. Полный JWT и пароли не должны попадать на скриншоты.

### Обработка и закрытие

```bash
curl -i -X PATCH "http://127.0.0.1:8080/api/incidents/$INCIDENT_ID/status" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"status":"IN_PROGRESS"}'
curl -i -X PATCH "http://127.0.0.1:8080/api/incidents/$INCIDENT_ID/status" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"status":"CLOSED"}'
```

Ожидается 200 для обоих переходов. Попытка вернуть CLOSED в IN_PROGRESS должна дать 409.
После перезапуска с той же базой запись и её статус должны сохраниться; токен при смене ключа нужно получить заново.

### Проверки безопасности

```bash
BOB_TOKEN="$(./scripts/login.sh bob)"
curl -i http://127.0.0.1:8080/api/data -H "Authorization: Bearer $BOB_TOKEN"
curl -i -X PATCH "http://127.0.0.1:8080/api/incidents/$INCIDENT_ID/status" \
  -H "Authorization: Bearer $BOB_TOKEN" -H 'Content-Type: application/json' \
  --data '{"status":"IN_PROGRESS"}'
curl -i http://127.0.0.1:8080/api/incidents \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"title":"XSS demo","description":"<script>alert(1)</script>","category":"OTHER","severity":"LOW"}'
printf '%s' "alice' OR 1=1 --" | jq -Rs '{username: ., password: "wrong-password"}' | \
  curl -i http://127.0.0.1:8080/auth/login -H 'Content-Type: application/json' --data-binary @-
unset TOKEN BOB_TOKEN
```

Ожидается отсутствие инцидента alice у bob, 404 при изменении чужой записи,
экранированный description и 401 при SQLi в логине. Дополнительно проверяются
неверный JWT, owner_id в JSON, severity=0, тело больше 16 КиБ и лимит входа.

## Защита

SQLi: значения передаются через ? / PreparedStatement; конкатенации ввода с SQL нет.
Авторизация: чтение и изменение ограничены owner_id из JWT. Изменение статуса транзакционно.
XSS: исходный текст хранится в базе, title/description экранируются через HtmlUtils.htmlEscape
при выдаче во всех трёх защищённых методах. JSON не является HTML; будущий клиент должен
безопасно выводить текст и не вставлять декодированные строки в innerHTML.

BCrypt(cost=12) хранит соль и хэш; проверка через matches. JWT подписан HS256,
живёт 900 секунд; проверяются подпись, sub/exp/iat/nbf/iss/aud и наличие пользователя.
Ключ - минимум 32 случайных байта. JWT не шифрует payload, пароль в него не включается.
Ошибки входа одинаковы для неизвестного пользователя и неверного пароля.

Тело ограничено 16 КиБ; вход - 10 запросов в минуту с IP в одном процессе.
Числа/boolean не преобразуются в строки; enum не принимают числовые индексы.
Неизвестные JSON-поля и хвостовые токены отклоняются. Настроены nosniff, CSP, DENY, no-store.
CSRF отключён для stateless Bearer API без cookie/session/Basic-аутентификации.

Это учебный сервис: нет командного доступа, refresh token, MFA, индивидуального отзыва JWT,
журнала всех изменений и полного поиска по истории. Лимит IP локален одному процессу.
Модель не заявляет полного покрытия OWASP Top 10 или готовности к промышленной эксплуатации.

## CI и проверка

.github/workflows/ci.yml содержит api-tests, sast и sca; запуск при push, pull_request и вручную.
SAST анализирует production-байткод категории SECURITY. Три узких исключения документированы
в config/spotbugs/reviewed-exclusions.xml: stateless CSRF, инвентаризация четырёх известных
методов контроллера и чтение длины Authorization. XSS_SERVLET не исключён.

SCA проверяет прямые и транзитивные runtime-зависимости по публичным NVD feeds.
Ключ Snyk/NVD не требуется; OSS Index выключен. Тестовый/build classpath не охвачен.
CVSS ≥ 7 и ошибки инструмента блокируют job; отдельный контроль SHA-256 требует все рабочие JAR
в JSON-отчёте. Отчёты сохраняются через if: always(). Actions закреплены по SHA.

После отдельного разрешения на запуск:

```bash
./gradlew --no-daemon --console=plain build test dependencyCheckAnalyze
```

Это команды для будущей проверки. Новых результатов пока нет.
Архив отчётов по заметкам находится в docs/evidence/notes-2026-10-25/ и не является проверкой инцидентов.

Перед сдачей нужны новая локальная проверка, публикация актуального кода, успешный CI
для этого коммита и реальные скриншоты: вход, создание и обработка инцидента, отказ
при изменении чужой записи, SQLi/XSS, успешные api-tests/sast/sca с SHA коммита.
Пароли, JWT и ключи на снимках необходимо закрывать.

Ветка проекта: main. Сообщение коммита с журналом инцидентов: first commit.
Старые 19 тестов и 15 HTTP-проверок от 25.10.2026 не подтверждают новую версию.
Последний успешный pipeline: пока не подтверждён. Отправка преподавателю не выполнялась.
# infosec-lab1
# infosec-lab1
