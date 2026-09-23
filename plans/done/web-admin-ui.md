---
Название: "Безопасный Web UI для TrustTunnel"
Сложность: hard
Важность: 3
Дата завершения: 2026-09-23
---

## Что мы делаем?

Строим server-rendered админку на `html/template`, Bootstrap и htmx с локальными embedded-ассетами. MVP включает обязательную инициализацию администратора, защищённые сессии, статус endpoint, CRUD VPN-пользователей, enable/disable/revoke, генерацию QR, `tt://` и client TOML через service layer, настройки домена/TLS, ограниченные логи и ошибки apply. SPA, Node, CDN, публичная регистрация и дублирующий JSON API не входят в план.

## Для чего мы делаем?

Официальный endpoint не имеет серверной админки, а найденные community-панели либо заменяют endpoint собственной версией, либо требуют опасных привилегий. UI должен быть тонким клиентом уже проверенных controller services, не обходить транзакции и не получать доступ к Docker или хосту.

## План

- [x] Зафиксировать HTTP-архитектуру и границы Web MVP
  - [x] Описать server-rendered маршруты для bootstrap, login/logout, dashboard, VPN users, client configs, TLS settings и apply events.
  - [x] Отделить handlers от controller services и запретить handlers напрямую изменять SQLite, TOML и child process.
  - [x] Использовать HTML-ответы и htmx fragments вместо дублирующего SPA API.
  - [x] Оставить health/readiness endpoints машиночитаемыми и без админской сессии.
  - [x] Привязать UI по умолчанию к loopback или внутреннему Compose listener, не к публичному интерфейсу.

- [x] Собрать embedded frontend без Node и CDN
  - [x] Зафиксировать конкретные версии Bootstrap и htmx.
  - [x] Сохранить minified-ассеты в исходном дереве с файлами лицензий и checksums upstream-артефактов.
  - [x] Встроить templates, CSS, JavaScript и иконки через `embed`.
  - [x] Добавить cache busting и корректные Content-Type/Cache-Control для embedded assets.
  - [x] Не добавлять npm, runtime CDN и inline-скрипты, мешающие строгой CSP.

- [x] Реализовать обязательную инициализацию администратора
  - [x] Переводить новую инсталляцию в bootstrap-режим, если в SQLite нет администратора.
  - [x] Требовать явно заданный сильный пароль и не иметь default credentials.
  - [x] Хешировать пароль Argon2id с зафиксированными и тестируемыми memory/time/parallelism parameters.
  - [x] Не открывать остальные UI-маршруты до завершения bootstrap.
  - [x] Деактивировать bootstrap-маршрут после успешной транзакции.

- [x] Защитить аутентификацию и сессии
  - [x] Хранить случайный session token в SQLite только в виде криптографического хеша.
  - [x] Устанавливать session cookie с `Secure`, `HttpOnly`, `SameSite` и ограниченным lifetime.
  - [x] Ротировать session ID после login и после изменения пароля.
  - [x] Инвалидировать session при logout, password change, удалении админа и expiry.
  - [x] Сравнивать секреты за константное время и возвращать одинаковые login errors без user enumeration.
  - [x] Ограничить login attempts по IP и логину с окном, backoff и ограниченной памятью.
  - [x] Не доверять `X-Forwarded-*`, если запрос не пришёл от явно разрешённого reverse proxy.

- [x] Защитить HTTP-слой от мутаций и внедрений
  - [x] Выдавать session-bound CSRF token и проверять его для каждого POST/PUT/PATCH/DELETE и htmx-запроса.
  - [x] Отклонять state-changing GET-маршруты.
  - [x] Задать CSP, `X-Content-Type-Options`, `Referrer-Policy`, frame restrictions и корректный HSTS для внешнего TLS-режима.
  - [x] Ограничить request body, multipart size, header size и request timeout.
  - [x] Полагаться на auto-escaping `html/template` и не передавать пользовательские строки как trusted HTML/JS.
  - [x] Добавить один request ID на запрос и не писать в access log cookie, CSRF token, пароли и deeplink.

- [x] Создать dashboard состояния endpoint
  - [x] Показать версию официального endpoint, PID, uptime, статус, текущую config revision и TLS expiry.
  - [x] Показать ограниченный набор агрегированных Prometheus-метрик без username и client IP.
  - [x] Обновлять status fragments через htmx с ограниченной частотой.
  - [x] Различать stopped, starting, ready, degraded и crash-loop без ложного зелёного статуса.

- [x] Реализовать CRUD VPN-пользователей
  - [x] Показать список с однозначными статусами active, disabled и revoked.
  - [x] Создавать VPN-пользователя с валидированным уникальным username и криптостойким случайным паролем.
  - [x] Показывать вновь созданный VPN-пароль в явном виде только в нужном workflow и не включать его в списки и логи.
  - [x] Перевыпускать credentials отдельной мутацией с подтверждением.
  - [x] Применять enable/disable/revoke через controller service с restart endpoint и rollback при ошибке.
  - [x] Отличать обратимое disable от необратимого revoke в UI и диалоге подтверждения.

- [x] Добавить выдачу клиентских конфигов
  - [x] Получать `tt://` и client TOML только через official CLI service из ядра контроллера.
  - [x] Проверять активный статус пользователя и readiness endpoint до экспорта.
  - [x] Генерировать QR из готового official deeplink локальной Go-библиотекой.
  - [x] Ограничить QR payload size, dimensions и время генерации.
  - [x] Задать `Cache-Control: no-store` для deeplink, QR и client TOML.
  - [x] Не помещать deeplink и client TOML в URL query, browser history и application logs.

- [x] Реализовать экран домена и сертификата
  - [x] Показать активный hostname, ACME mode, staging flag, issuer, fingerprint, expiry и last renewal error.
  - [x] Валидировать hostname и email до вызова certificate service.
  - [x] Разделить операции сохранения настроек и явного issue/renew.
  - [x] Показать предупреждение, что staging-сертификат не доверен клиентами.
  - [x] Не включать DNS-01 в MVP-формы.

- [x] Добавить ограниченный просмотр логов и apply-ошибок
  - [x] Показывать bounded ring buffer логов контроллера и endpoint без доступа к произвольным файлам.
  - [x] Редактировать credentials, cookie, CSRF token, ACME token, private key и deeplink до попадания в буфер.
  - [x] Показывать apply history с revision, типом изменения, restart/SIGHUP, результатом и санитизированной ошибкой.
  - [x] Ограничить pagination и частоту htmx-обновлений.

- [x] Покрыть Web UI автоматическими проверками
  - [x] Добавить handler-тесты bootstrap, login/logout, expiry, session rotation, invalidation и rate limiting.
  - [x] Добавить negative-тесты CSRF, XSS, open redirect, oversized body, malformed form и forged proxy headers.
  - [x] Добавить service-level integration-тесты CRUD с проверкой restart, rollback и итогового `credentials.toml`.
  - [x] Добавить browser-тесты ключевых workflow без CDN и внешней сети.
  - [x] Проверить cookies и security headers за reverse proxy и при прямом loopback-доступе.
  - [x] Проверить, что assets загружаются из образа, а browser network log не содержит CDN-запросов.
