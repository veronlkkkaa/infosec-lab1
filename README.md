# Лабораторная работа № 1: защищённый REST API

**Kotlin + Spring Boot.** Secure Notes API выдаёт JWT при входе, сохраняет личные заметки
и возвращает только записи текущего пользователя. Дисциплина - «Информационная безопасность».

**Автор:** Гаврилович Вероника Вячеславовна, Р3431.

**Статус на 25.10.2026:** сборка успешна; **19 тестов и 15 HTTP-сценариев прошли**.
SAST: 0 итоговых находок с тремя описанными правилами исключения. SCA: 70 рабочих JAR,
все SHA-256 подтверждены, 0 CVE. Подробности: [VERIFICATION.md](docs/VERIFICATION.md).
Публичный репозиторий создан; GitHub Actions ещё не подтверждён. PDF остаётся черновиком до
добавления ссылок и реальных скриншотов. [Как завершить публикацию](docs/PUBLISH.md).

## Стек

| Компонент | Выбор |
|---|---|
| Язык | Kotlin 2.4.21 |
| Backend | Spring Boot 4.1.2, Spring MVC |
| Аутентификация | Spring Security, OAuth2 Resource Server, Nimbus JWT |
| Хранение | Файловая H2, Spring JDBC / JdbcTemplate |
| Пароли | BCrypt, cost 12 |
| JVM и сборка | JDK 21, Gradle Wrapper 8.14.5, Kotlin DSL |
| Проверки поведения | JUnit Jupiter, Spring Boot Test, MockMvc |
| SAST | SpotBugs 4.10.4 + Find Security Bugs 1.14.0 |
| SCA | OWASP Dependency-Check 13.0.0 |

Версии сверены по официальным метаданным и документации 25.10.2026. После находок SCA
проект обновлён на Spring Boot 4.1.2, Kotlin 2.4.21 и Jackson 3; проверки повторены.
Spring Boot BOM и Kotlin BOM подключены через Gradle `platform` только к зависимостям
приложения и тестов. Это сохраняет собственные версии библиотек анализатора SpotBugs.
Зависимости разрешены при сборке 25.10.2026; полный Gradle lock-файл пока не создавался.

## Открытие проекта

В IntelliJ IDEA: **File → Open**, выбрать эту папку и импортировать Gradle-проект.
Настроить **Project SDK = JDK 21** и **Gradle JVM = JDK 21**. Поддержка Kotlin встроена в IDEA.
Импорт Gradle может скачать зависимости и выполнить задачи модели проекта; агент его не запускал.

В VS Code: **File → Open Folder**, выбрать эту папку. Исходники лежат в
`src/main/kotlin/ru/itmo/infosec/lab1`. Для работы с JVM/Spring можно установить
Extension Pack for Java и Spring Boot Extension Pack из рекомендаций проекта.
Расширения редактора и JDK сами собой не устанавливаются.

## Структура

```text
build.gradle.kts              зависимости, JVM, тесты и SpotBugs
settings.gradle.kts           имя проекта
gradlew / gradlew.bat         официальный Gradle Wrapper
gradle/wrapper/               JAR wrapper и checksum дистрибутива
src/main/kotlin/.../lab1/
  Application.kt              точка входа
  SecurityConfig.kt           JWT и SecurityFilterChain
  JsonConfig.kt               строгие типы строковых полей JSON
  AuthService.kt              проверка пароля и выдача JWT
  ApiController.kt            три HTTP-метода
  ApiModels.kt                DTO и правила проверки текста
  Repositories.kt             параметризованные SQL-запросы
  BootstrapUsers.kt           первоначальное создание аккаунтов
  RequestGuardFilter.kt       ограничение тела и частоты входа
  ApiExceptionHandler.kt      стабильные JSON-ошибки
src/main/resources/           настройки и SQL-схема
src/test/kotlin/.../          19 сценариев JUnit/MockMvc
scripts/run-local.sh          интерактивный запуск
scripts/login.sh              вход через curl со скрытым вводом пароля
.github/workflows/ci.yml      CI при push, pull_request и ручном запуске
config/spotbugs/              категория SECURITY и три узких правила исключения
docs/                        отчёт, подготовка к защите, статус проверок
```

## Запуск на macOS/Linux

Нужны **JDK 21** и интернет для первого скачивания Gradle и зависимостей.
Для curl-примеров нужны curl и jq; скрипт запуска генерирует ключ через openssl.
На macOS выбрать установленный JDK 21 можно так:

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 21)"
export PATH="$JAVA_HOME/bin:$PATH"
./scripts/run-local.sh
```

Если JDK установлен вручную и `java_home` его не видит, укажите каталог JDK напрямую.
На компьютере, где выполнена проверка, использовался:

```bash
export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/arcadia-jdk-21"
./gradlew --no-daemon --console=plain build test
```

Если JDK 21 отсутствует, установите его или скачайте через IDEA. JDK 25 не следует
использовать как Gradle JVM для выбранной связки Gradle 8.14.5. Глобальная установка Gradle не нужна.
**Скрипт запускает `bootRun`, который компилирует и запускает приложение.** При подготовке
скрипт не выполнялся. В Windows доступны `gradlew.bat`; shell-помощники рассчитаны на bash.

Скрипт скрыто запросит пароли для alice и bob и сгенерирует случайный ключ JWT.
Пароль: не меньше 15 символов и не больше 72 байт UTF-8. Это учитывает ограничение BCrypt;
слишком длинные пароли отклоняются, а не молча обрезаются. Приложение:
`http://127.0.0.1:8080`. База: `data/lab.mv.db`; создаётся при первом запуске.

При ручном запуске настройка эквивалентна:

```bash
export JWT_SECRET_BASE64="$(openssl rand -base64 48)"
# LAB_PASSWORD и LAB_SECOND_PASSWORD задайте через скрытый ввод в run-local.sh
./gradlew --no-daemon bootRun
```

Без пароля отсутствующего первого пользователя приложение откажется стартовать. Второй
аккаунт создаётся только при заданном LAB_SECOND_PASSWORD. Уже существующий аккаунт не
перезаписывается: ввод другого пароля при повторном старте не меняет сохранённый хэш.
`LAB_USERNAME` и `LAB_SECOND_USERNAME` меняют имена создаваемых аккаунтов.

При генерации нового JWT-ключа ранее выданные токены перестают проходить проверку.
Для постоянного ключа задайте JWT_SECRET_BASE64 заранее; не сохраняйте его в репозиторий.
`.env.example` - памятка: автоматической загрузки `.env` нет. Параметры DATABASE_URL,
DATABASE_USERNAME и DATABASE_PASSWORD позволяют изменить настройки H2.
H2 работает внутри процесса, TCP-сервер и веб-консоль не включены. Для внешнего доступа
к API нужны HTTPS и отдельная эксплуатационная настройка.

## API

| Метод | Тело JSON | Успешный ответ |
|---|---|---|
| `POST /auth/login` | `username`, `password` | 200: `access_token`, `token_type`, `expires_in` |
| `GET /api/data` | нет | 200: `items`, последние 100 своих заметок |
| `POST /api/notes` | `title`, `content` | 201: созданная заметка |

Оба `/api/*`-метода требуют `Authorization: Bearer <token>`.
`title` - непустой текст до 120 UTF-16 единиц; `content` - до 2000.
ID владельца берётся из JWT; присланный `owner_id` и любые лишние JSON-поля отклоняются.
Основные ошибки: 400 - ввод; 401 - аутентификация; 403 - запрещённый маршрут;
405 - метод; 413 - тело более 16 КиБ; 415 - не JSON; 429 - лимит входа.
Ответ имеет вид `{"error":"unauthorized"}` без паролей и внутренних SQL-ошибок.

## Демонстрация через curl

Ниже команды для самостоятельного повторения. Отдельно выполнены 15 curl-сценариев
на временном стенде; реальные ответы сохранены в docs/evidence/local-2026-10-25/http-results.html.
Сервер работает в первом терминале, команды — во втором. На снимках скрывайте полный JWT.

### 1. Отказ без токена и успешный вход

```bash
curl -i http://127.0.0.1:8080/api/data
TOKEN="$(./scripts/login.sh alice)"
curl -i http://127.0.0.1:8080/api/data -H "Authorization: Bearer $TOKEN"
```

Ожидается сначала 401, затем 200. У нового пользователя список `items` пуст.
`login.sh` скрыто запрашивает пароль, отправляет POST /auth/login через curl и выдаёт JWT
для сохранения в переменную TOKEN. Пароль не передаётся аргументом процесса jq/curl.

### 2. Создание заметки и XSS

```bash
curl -i http://127.0.0.1:8080/api/notes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"title":"XSS demo","content":"<script>alert(1)</script>"}'
curl -i http://127.0.0.1:8080/api/data -H "Authorization: Bearer $TOKEN"
```

Ожидается 201 при создании, 200 при чтении и текст
`&lt;script&gt;alert(1)&lt;/script&gt;`. Исходный текст сохраняется в БД;
экранирование применяется при формировании ответа, поэтому повторное чтение не кодирует его дважды.

### 3. SQLi в логине

```bash
printf '%s' "alice' OR 1=1 --" |
  jq -Rs '{username: ., password: "wrong-password"}' |
  curl -i http://127.0.0.1:8080/auth/login \
    -H 'Content-Type: application/json' --data-binary @-
```

Ожидается 401: вся строка сравнивается с логином как значение параметра SQL.

### 4. Неверный токен, подмена владельца и чужие заметки

```bash
curl -i http://127.0.0.1:8080/api/data -H 'Authorization: Bearer broken'
curl -i http://127.0.0.1:8080/api/notes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"title":"T","content":"C","owner_id":2}'
BOB_TOKEN="$(./scripts/login.sh bob)"
curl -i http://127.0.0.1:8080/api/data -H "Authorization: Bearer $BOB_TOKEN"
unset TOKEN BOB_TOKEN
```

Ожидается 401 для токена, 400 для подмены владельца и пустой список bob, если он ещё ничего
не создавал. После 10 входов с одного IP за минуту следующий получает 429; перед повторной
демонстрацией можно подождать минуту.

## Как устроена защита

- **SQLi:** `JdbcTemplate` передаёт значения через `?`; создание заметки использует
  PreparedStatement. В SQL нет конкатенации пользовательского текста.
- **XSS:** `HtmlUtils.htmlEscape` применяется к title/content в ответе. JSON имеет правильный
  Content-Type; Spring Security добавляет `nosniff`, CSP и запрет встраивания во фрейм.
  HTML-экранирование не универсально для JavaScript/CSS/URL. Будущий frontend должен выводить
  данные безопасно и не декодировать их для вставки в `innerHTML`.
- **Пароли:** `BCryptPasswordEncoder(12)` создаёт соль и хэш. В БД хранится только хэш;
  при входе используется `matches`. Для отсутствующего пользователя проверяется dummy hash,
  а текст ошибки одинаков для неверного пароля и неизвестного логина.
- **JWT:** HS256, ключ минимум 32 случайных байта после Base64-декодирования, срок 900 секунд.
  Проверяются подпись, sub/exp/iat/nbf/iss/aud, временные границы, издатель, аудитория и
  существование пользователя. JWT подписан, но не зашифрован; пароль в него не помещается.
- **Доступ к данным:** фильтрация `WHERE owner_id = ?`, владелец берётся из проверенного токена.
- **Границы запросов:** тело до 16 КиБ, в том числе при неизвестном Content-Length;
  валидация DTO, запрет неизвестных полей и скалярных преобразований типов.
- **Сессии и CSRF:** API принимает только явно переданный Bearer-заголовок; сессии, form login
  и HTTP Basic выключены. В этой модели CSRF отключён осознанно. Если появится аутентификация
  через автоматически отправляемые браузером cookies, защиту от CSRF нужно пересмотреть.

Лимит входа локален одному процессу, сбрасывается при его перезапуске и не защищает от
распределённого перебора. Нет индивидуального отзыва JWT, refresh token, MFA и восстановления
пароля. Удаление пользователя или смена ключа делает его токен недействительным.
Реализация не заявляет полного покрытия OWASP Top 10.

## CI и отчёты безопасности

Workflow запускается на push, pull_request и workflow_dispatch. Три job:

| Job | Команда | Отчёт |
|---|---|---|
| api-tests | `./gradlew --no-daemon test` | `build/reports/tests/test/`, `build/test-results/test/` |
| sast | `./gradlew --no-daemon spotbugsMain` | `build/reports/spotbugs/main.html` и `.xml` |
| sca | `./gradlew --no-daemon dependencyCheckAnalyze` | `build/reports/dependency-check/` |

SpotBugs с Find Security Bugs анализирует production-байткод категории SECURITY.
25.10.2026 анализ 27 class-файлов завершился успешно: 0 находок, 0 ошибок, 0 missing classes
в итоговом XML. Все уровни уверенности включены; `ignoreFailures=false`.
В `config/spotbugs/reviewed-exclusions.xml` документированы три узких правила:

- `SPRING_CSRF_PROTECTION_DISABLED` только для SecurityConfig.securityFilterChain и его
  Kotlin-лямбд: stateless Bearer API без cookie/session/Basic-аутентификации.
- `SPRING_ENDPOINT` только для трёх существующих методов ApiController: информационная
  инвентаризация эндпоинтов. Login проверяет пароль; методы заметок требуют JWT и владельца.
- `SERVLET_HEADER` только для RequestGuardFilter.doFilterInternal: чтение длины недоверенного
  Authorization для отсечения слишком длинного заголовка. Подпись и claims проверяет Nimbus.

Предупреждение `XSS_SERVLET` устранено заменой ручной конкатенации JSON-ошибок сериализацией.
Для него исключения нет. Новые классы и типы находок этими правилами не скрываются.
Результат относится к текущему коду и указанным фильтрам, а не ко всем возможным уязвимостям.

OWASP Dependency-Check 13.0.0 проверяет прямые и транзитивные runtime-зависимости
по публичным NVD feeds. API-ключ и Snyk-аккаунт не нужны. Дополнительный OSS Index отключён,
поскольку требует авторизации; NVD-анализ включён. Ошибки инструмента и CVSS ≥ 7 блокируют job.
Ниже порога находки остаются в отчёте. Тестовые зависимости и инструменты сборки не охвачены.

```bash
./gradlew --no-daemon dependencyCheckAnalyze
```

Явно выбран runtimeClasspath; skipTestGroups=false нужен из-за родительской конфигурации
Spring Boot testAndDevelopmentOnly. Дополнительная проверка SHA-256 требует, чтобы каждый
рабочий JAR присутствовал в JSON. Пустой/неполный отчёт не считается успешным. Задача
не пропускает анализ как UP-TO-DATE, поэтому повторный вызов проверяет актуальность базы.
Первый запуск требует интернета и скачивания NVD; при ошибке данных сборка SCA падает.

25.10.2026: 70 рабочих JAR, 0 CVE. После первоначальных 46 уникальных CVE обновлены
Kotlin, Spring Boot и связанные библиотеки. Исключения уязвимостей не добавлялись.

Отчёты загружаются с if: always(), если созданы. Actions закреплены по SHA,
Gradle Wrapper — по SHA-256. Полный lock-файл зависимостей пока не создавался.

## Проверки и сдача

19 JUnit/MockMvc-сценариев проверили настоящий SecurityFilterChain, подпись JWT, SQLi,
экранирование, изоляцию владельцев, валидацию, лимиты и заголовки. Добавлен регрессионный
тест для Integer/Float/Boolean в строковых полях заметок и логина; расширена проверка
слишком длинного Authorization. В итоговом запуске: 19 passed, 0 failed, 0 skipped.

Тесты используют Spring-контекст и H2 in-memory; создание первоначальных пользователей
отключено. MockMvc не поднимает сетевой HTTP-сервер и не заменяет демонстрацию curl.

Результаты локального запуска:

- [JUnit HTML](build/reports/tests/test/index.html).
- [SpotBugs HTML](build/reports/spotbugs/main.html) и [XML](build/reports/spotbugs/main.xml).
- Исполняемый JAR: `build/libs/lab1-secure-api-1.0.0.jar`.
- [Статус и исправления](docs/VERIFICATION.md); [сводка из XML](docs/verification-2026-10-25.json).

Каталог build не входит в исходный ZIP. Копии SAST/SCA и HTTP-протокол находятся
в docs/evidence/local-2026-10-25/ и включены в архив.

Перед сдачей нужно:

1. Опубликовать подготовленный коммит в публичный репозиторий; ветка main согласована. См. docs/PUBLISH.md.
2. Получить успешный GitHub Actions для финального коммита.
3. Добавить реальные скриншоты, URL репозитория и запуска в README и PDF.
4. Защитить и отправить PDF на google@niuitmo.ru. Тема: «Гаврилович В. В., Р3431, работа 1».
   Письмо не отправлялось.

**Публичный репозиторий:** [veronlkkkaa/infosec-lab1](https://github.com/veronlkkkaa/infosec-lab1).
**Последний успешный pipeline:** отсутствует.
**Скриншоты:** пока не получены; перечень - `docs/screenshots/README.md`.

## Источники

- Методичка «Лабораторные работы 2025», с. 1-4, и текстовое уточнение преподавателя.
- [Spring Boot 3.5: требования](https://docs.spring.io/spring-boot/4.1/system-requirements.html).
- [Spring Boot: Kotlin](https://docs.spring.io/spring-boot/4.1/reference/features/kotlin.html).
- [Kotlin и совместимость Gradle](https://kotlinlang.org/docs/gradle-configure-project.html).
- [Spring Security: JWT](https://docs.spring.io/spring-security/reference/7.1/servlet/oauth2/resource-server/jwt.html).
- [SpotBugs Gradle Plugin](https://github.com/spotbugs/spotbugs-gradle-plugin).
- [Find Security Bugs](https://find-sec-bugs.github.io/bugs.htm).
- [OWASP Dependency-Check Gradle](https://dependency-check.github.io/DependencyCheck/dependency-check-gradle/configuration.html).
- [Gradle Wrapper](https://docs.gradle.org/current/userguide/gradle_wrapper.html).
