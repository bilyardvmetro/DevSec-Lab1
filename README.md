# Лабораторная работа 1 — защищённый REST API на Go

Разработка защищённого REST API с интеграцией проверок безопасности в CI/CD.
Учебный сервис хранит личные заметки в SQLite. Реализованы JWT-аутентификация,
bcrypt, параметризованные SQL-запросы и экранирование пользовательских строк.

## Стек и запуск

Go 1.26.9, net/http, SQLite (github.com/mattn/go-sqlite3, требуется C-компилятор),
github.com/golang-jwt/jwt/v5, golang.org/x/crypto/bcrypt. Версии зависимостей
зафиксированы в go.mod и go.sum. Linux/macOS; для SQLite включён CGO.

```bash
git clone https://github.com/bilyardvmetro/DevSec-Lab1.git
cd DevSec-Lab1
go mod download
go build -o bin/hash ./cmd/hash
go build -o bin/api ./cmd/api
export ADMIN_USERNAME=student
read -rs -p 'Пароль (12–72 байта): ' PASSWORD; echo
export ADMIN_PASSWORD_HASH=$(printf '%s\n' "$PASSWORD" | ./bin/hash)
unset PASSWORD
export JWT_SECRET=$(openssl rand -base64 32)
./bin/api
```

Команды ввода пароля выше предназначены для bash. Сервер слушает
127.0.0.1:8080. LISTEN_ADDR позволяет выбрать другой loopback-адрес и порт.
При первом запуске создаются lab.db и пользователь из ADMIN_USERNAME;
при повторном запуске его хеш обновляется из ADMIN_PASSWORD_HASH.
JWT_SECRET — случайный ключ не короче 32 байт в Base64. Сохраняйте его в
менеджере секретов, если токены должны оставаться действительными после перезапуска.
Секреты, пароль, токены и база не коммитятся. Для удалённого доступа необходим
HTTPS reverse proxy; сервер отказывается слушать публичный IP.

## API и примеры curl

Все тела запросов — JSON. Примеры выполняются в bash.

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| POST | /auth/login | без JWT | Логин и выдача токена на 15 минут |
| GET | /api/data | Bearer JWT | Последние 100 заметок текущего пользователя |
| POST | /api/data | Bearer JWT | Создание своей заметки |

```bash
# Без токена: 401
curl -i http://127.0.0.1:8080/api/data

# Вход: введите тот же пароль; тело не включается в историю команд.
read -rs -p 'Пароль: ' PASSWORD; echo
TOKEN=$(printf '%s' "$PASSWORD" | python3 -c 'import json,sys; print(json.dumps({"username":"student","password":sys.stdin.read()}))' | curl -fsS -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8080/auth/login | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
unset PASSWORD

# Создание: 201; пользовательские строки экранированы
curl -i -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Первая заметка","content":"<script>alert(1)</script>"}' \
  http://127.0.0.1:8080/api/data

# Получение: 200
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/data
unset TOKEN
```

Успешный login возвращает access_token, token_type=Bearer и expires_in=900.
Заметка содержит id, title, content. Ошибки имеют поле error: 400 — неверный
JSON/поля, 401 — аутентификация, 413 — тело больше 4096 байт, 415 — другой
Content-Type, 429 — превышен лимит входа. Заголовок заметки — 1–100 байт
после TrimSpace; содержимое — до 2000 байт (для UTF-8 байты не равны символам).

## Реализованные меры защиты

- **SQLi:** все пользовательские значения передаются отдельно в параметры `?`
  через database/sql. SQL не собирается конкатенацией. Ввод `' OR 1=1 --`
  не обходит вход, строка `'; DROP TABLE users; --` сохраняется как данные.
- **XSS:** строки title/content проходят html.EscapeString при выдаче обоими
  методами; encoding/json дополнительно экранирует HTML-символы. Ответы имеют
  application/json, X-Content-Type-Options: nosniff и CSP default-src 'none'.
  Клиент должен использовать textContent и не декодировать строки в innerHTML.
- **Пароли:** bcrypt с cost=12 и случайной солью. В SQLite хранится только хеш.
  Для неизвестного пользователя тоже выполняется bcrypt-проверка; сообщение
  ошибки одинаковое для неизвестного логина и неверного пароля.
- **JWT:** HS256, allowlist алгоритма, обязательный exp, проверка iss, aud,
  nbf и iat при наличии; sub должен соответствовать существующему пользователю.
  Подпись, срок и назначение токена проверяет middleware обоих защищённых методов.
  Payload подписан, но не зашифрован; секретов и пароля в нём нет.
- **Авторизация:** owner_id берётся только из проверенного sub. Чтение фильтруется
  по owner_id. Передать чужой owner_id в JSON нельзя.
- **Ограничения:** максимум 4096 байт на тело, запрет неизвестных полей и второго
  JSON-объекта, серверные таймауты и максимум 8192 байта заголовков. Не более 20
  запросов входа за минуту на процесс, после этого 429 с Retry-After.
- **Эксплуатация:** loopback по умолчанию и обязательный TLS-прокси для сети,
  права новых файлов 0600 (umask 0077), Cache-Control: no-store. Пароли и JWT
  не записываются в журнал. Это учебный сервис: нет регистрации, refresh,
  отзыва JWT, MFA, распределённого rate limit и автоматического развёртывания.
  Глобальный лимит входа позволяет одному клиенту временно ограничить других;
  в production нужен распределённый лимит по аккаунту/IP с доверенным прокси.

## Тестирование и CI/CD

```bash
go test -race -cover -v ./...
go vet ./...
bash scripts/smoke.sh
go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
gosec -fmt=json -out=gosec.json ./...
govulncheck ./...
```

scripts/smoke.sh поднимает временный сервер и выполняет реальные curl-запросы.
Тесты проверяют вход, SQLi, XSS, чужие данные, неверную подпись, alg=none,
другой алгоритм, просроченный JWT, отсутствие exp, неверные iss/aud, будущий nbf,
неизвестный sub, ограничения JSON, rate limit и отказ при слабой конфигурации.

.github/workflows/ci.yml запускается на каждый push и pull_request, а также
вручную. Этапы: проверка зависимостей → gofmt/vet → race-тесты → SAST gosec →
SCA govulncheck → сборка → curl. Ошибка сканера завершает pipeline неуспешно.
Отчёты сохраняются как artifact security-reports на 30 дней даже при ошибке.
Workflow имеет только contents: read, не получает секреты и не развёртывает сервис.

[Запуски GitHub Actions](https://github.com/bilyardvmetro/DevSec-Lab1/actions)

## Теоретические вопросы

1. bcrypt медленный и адаптивный, использует уникальную соль и настраиваемую
   стоимость. Быстрый SHA-256 облегчает массовый перебор паролей.
2. SAST анализирует исходный код без запуска приложения; DAST отправляет запросы
   работающему приложению. SCA ищет известные уязвимости компонентов.
3. JWT состоит из header, payload и signature. HS256 подписывает первые две
   Base64URL-части общим секретом. Сервер проверяет подпись и claims;
   декодирование Base64URL само по себе не доказывает подлинность.
4. Без аудита зависимостей остаются известные CVE и уязвимые транзитивные
   компоненты. Нужны регулярные проверки и обновления; чистый отчёт сканера
   не доказывает отсутствие всех возможных уязвимостей.

## Источники

- https://go.dev/doc/security/vuln/
- https://github.com/securego/gosec
- https://pkg.go.dev/golang.org/x/crypto/bcrypt
- https://golang-jwt.github.io/jwt/
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
