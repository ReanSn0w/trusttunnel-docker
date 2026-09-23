---
Название: "Безопасный Web UI для TrustTunnel"
Сложность: hard
Важность: 3
---

## Что мы делаем?

Строим server-rendered админку на `html/template`, Bootstrap и htmx с локальными embedded-ассетами. MVP включает обязательную инициализацию администратора, защищённые сессии, статус endpoint, CRUD VPN-пользователей, enable/disable/revoke, генерацию QR, `tt://` и client TOML через service layer, настройки домена/TLS, ограниченные логи и ошибки apply. SPA, Node, CDN, публичная регистрация и дублирующий JSON API не входят в план.

## Для чего мы делаем?

Официальный endpoint не имеет серверной админки, а найденные community-панели либо заменяют endpoint собственной версией, либо требуют опасных привилегий. UI должен быть тонким клиентом уже проверенных controller services, не обходить транзакции и не получать доступ к Docker или хосту.

## План

- [ ] Зафиксировать HTTP-архитектуру и границы Web MVP
  - [ ] Описать server-rendered маршруты для bootstrap, login/logout, dashboard, VPN users, client configs, TLS settings и apply events.
  - [ ] Отделить handlers от controller services и запретить handlers напрямую изменять SQLite, TOML и child process.
  - [ ] Использовать HTML-ответы и htmx fragments вместо дублирующего SPA API.
  - [ ] Оставить health/readiness endpoints машиночитаемыми и без админской сессии.
  - [ ] Привязать UI по умолчанию к loopback или внутреннему Compose listener, не к публичному интерфейсу.

- [ ] Собрать embedded frontend без Node и CDN
  - [ ] Зафиксировать конкретные версии Bootstrap и htmx.
  - [ ] Сохранить minified-ассеты в исходном дереве с файлами лицензий и checksums upstream-артефактов.
  - [ ] Встроить templates, CSS, JavaScript и иконки через `embed`.
  - [ ] Добавить cache busting и корректные Content-Type/Cache-Control для embedded assets.
  - [ ] Не добавлять npm, runtime CDN и inline-скрипты, мешающие строгой CSP.

- [ ] Реализовать обязательную инициализацию администратора
  - [ ] Переводить новую инсталляцию в bootstrap-режим, если в SQLite нет администратора.
  - [ ] Требовать явно заданный сильный пароль и не иметь default credentials.
  - [ ] Хешировать пароль Argon2id с зафиксированными и тестируемыми memory/time/parallelism parameters.
  - [ ] Не открывать остальные UI-маршруты до завершения bootstrap.
  - [ ] Деактивировать bootstrap-маршрут после успешной транзакции.

- [ ] Защитить аутентификацию и сессии
  - [ ] Хранить случайный session token в SQLite только в виде криптографического хеша.
  - [ ] Устанавливать session cookie с `Secure`, `HttpOnly`, `SameSite` и ограниченным lifetime.
  - [ ] Ротировать session ID после login и после изменения пароля.
  - [ ] Инвалидировать session при logout, password change, удалении админа и expiry.
  - [ ] Сравнивать секреты за константное время и возвращать одинаковые login errors без user enumeration.
  - [ ] Ограничить login attempts по IP и логину с окном, backoff и ограниченной памятью.
  - [ ] Не доверять `X-Forwarded-*`, если запрос не пришёл от явно разрешённого reverse proxy.

- [ ] Защитить HTTP-слой от мутаций и внедрений
  - [ ] Выдавать session-bound CSRF token и проверять его для каждого POST/PUT/PATCH/DELETE и htmx-запроса.
  - [ ] Отклонять state-changing GET-маршруты.
  - [ ] Задать CSP, `X-Content-Type-Options`, `Referrer-Policy`, frame restrictions и корректный HSTS для внешнего TLS-режима.
  - [ ] Ограничить request body, multipart size, header size и request timeout.
  - [ ] Полагаться на auto-escaping `html/template` и не передавать пользовательские строки как trusted HTML/JS.
  - [ ] Добавить один request ID на запрос и не писать в access log cookie, CSRF token, пароли и deeplink.

- [ ] Создать dashboard состояния endpoint
  - [ ] Показать версию официального endpoint, PID, uptime, статус, текущую config revision и TLS expiry.
  - [ ] Показать ограниченный набор агрегированных Prometheus-метрик без username и client IP.
  - [ ] Обновлять status fragments через htmx с ограниченной частотой.
  - [ ] Различать stopped, starting, ready, degraded и crash-loop без ложного зелёного статуса.

- [ ] Реализовать CRUD VPN-пользователей
  - [ ] Показать список с однозначными статусами active, disabled и revoked.
  - [ ] Создавать VPN-пользователя с валидированным уникальным username и криптостойким случайным паролем.
  - [ ] Показывать вновь созданный VPN-пароль в явном виде только в нужном workflow и не включать его в списки и логи.
  - [ ] Перевыпускать credentials отдельной мутацией с подтверждением.
  - [ ] Применять enable/disable/revoke через controller service с restart endpoint и rollback при ошибке.
  - [ ] Отличать обратимое disable от необратимого revoke в UI и диалоге подтверждения.

- [ ] Добавить выдачу клиентских конфигов
  - [ ] Получать `tt://` и client TOML только через official CLI service из ядра контроллера.
  - [ ] Проверять активный статус пользователя и readiness endpoint до экспорта.
  - [ ] Генерировать QR из готового official deeplink локальной Go-библиотекой.
  - [ ] Ограничить QR payload size, dimensions и время генерации.
  - [ ] Задать `Cache-Control: no-store` для deeplink, QR и client TOML.
  - [ ] Не помещать deeplink и client TOML в URL query, browser history и application logs.

- [ ] Реализовать экран домена и сертификата
  - [ ] Показать активный hostname, ACME mode, staging flag, issuer, fingerprint, expiry и last renewal error.
  - [ ] Валидировать hostname и email до вызова certificate service.
  - [ ] Разделить операции сохранения настроек и явного issue/renew.
  - [ ] Показать предупреждение, что staging-сертификат не доверен клиентами.
  - [ ] Не включать DNS-01 в MVP-формы.

- [ ] Добавить ограниченный просмотр логов и apply-ошибок
  - [ ] Показывать bounded ring buffer логов контроллера и endpoint без доступа к произвольным файлам.
  - [ ] Редактировать credentials, cookie, CSRF token, ACME token, private key и deeplink до попадания в буфер.
  - [ ] Показывать apply history с revision, типом изменения, restart/SIGHUP, результатом и санитизированной ошибкой.
  - [ ] Ограничить pagination и частоту htmx-обновлений.

- [ ] Покрыть Web UI автоматическими проверками
  - [ ] Добавить handler-тесты bootstrap, login/logout, expiry, session rotation, invalidation и rate limiting.
  - [ ] Добавить negative-тесты CSRF, XSS, open redirect, oversized body, malformed form и forged proxy headers.
  - [ ] Добавить service-level integration-тесты CRUD с проверкой restart, rollback и итогового `credentials.toml`.
  - [ ] Добавить browser-тесты ключевых workflow без CDN и внешней сети.
  - [ ] Проверить cookies и security headers за reverse proxy и при прямом loopback-доступе.
  - [ ] Проверить, что assets загружаются из образа, а browser network log не содержит CDN-запросов.
