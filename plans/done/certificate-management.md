---
Название: "Управление TLS-сертификатами TrustTunnel"
Сложность: hard
Важность: 2
Дата завершения: 2026-09-23
---

## Что мы делаем?

Добавляем в Go-контроллер управление TLS: выпуск и продление Let's Encrypt через `go-acme/lego`, HTTP-01 на 80/TCP, staging-режим, атомарное хранение PEM, безопасное продление, rollback и SIGHUP endpoint. DNS-01 не входит в MVP; ручной сертификат поддерживается как ограниченный fallback.

## Для чего мы делаем?

Текущий shell-entrypoint может получить сертификат при первичной настройке, но не обеспечивает контролируемый renewal и безопасный rollback. Контроллер должен сам удерживать валидную TLS-цепочку, не подменять её при ошибке ACME и обновлять endpoint без разрыва активных сессий.

## План

- [x] Определить TLS domain model и границы MVP
  - [x] Описать состояния `unconfigured`, `issuing`, `active`, `renewing`, `degraded` и `manual` с однозначными переходами.
  - [x] Зафиксировать HTTP-01 как единственный автоматический challenge MVP.
  - [x] Отложить DNS-01 и провайдерские credentials до отдельного расширения.
  - [x] Ограничить manual fallback импортом PEM-цепочки и закрытого ключа без внешнего certbot.
  - [x] Увязать TLS-операции с apply-блокировкой и историей ревизий из ядра контроллера.

- [x] Добавить persistence ACME-аккаунта и метаданных сертификата
  - [x] Хранить ACME directory URL, account email, registration URI, статус, timestamps и последнюю ошибку в SQLite.
  - [x] Хранить ACME account key в persistent data directory с правами `0600`.
  - [x] Хранить serial, issuer, SAN, not-before, not-after, fingerprint и пути активной TLS-ревизии.
  - [x] Не сохранять private key, ACME account key или challenge token в application logs и apply history.

- [x] Интегрировать `go-acme/lego`
  - [x] Зафиксировать совместимую версию lego в Go module.
  - [x] Реализовать adapter ACME client, чтобы тесты не зависели от production Let's Encrypt.
  - [x] Создавать или восстанавливать ACME account идемпотентно.
  - [x] Разделить production и staging directory URL явным типизированным режимом.
  - [x] Отклонять непубличные hostname, IP вместо DNS-имени и невалидный email до вызова ACME.

- [x] Реализовать HTTP-01 challenge listener
  - [x] Открывать выделенный listener на 80/TCP только для challenge и ограниченных redirect/diagnostic ответов.
  - [x] Обслуживать только текущие challenge token по точному path.
  - [x] Ограничить header size, request timeout, idle timeout и число параллельных challenge-запросов.
  - [x] Удалять challenge state после завершения или отмены ACME-операции.
  - [x] Корректно завершать listener при SIGTERM контроллера.

- [x] Реализовать первичный выпуск сертификата
  - [x] Сериализовать issue/renew для одного hostname на контроллер.
  - [x] Ограничить всю ACME-операцию context timeout и корректно отменять её при shutdown.
  - [x] Проверять цепочку, SAN, сроки, соответствие private key и PEM encoding до публикации.
  - [x] Отклонять сертификат от staging CA при production-режиме.
  - [x] Записывать понятную ошибку в apply history без ACME token и key material.

- [x] Добавить атомарное хранение PEM и TLS rollback
  - [x] Создавать каталог TLS-ревизии с правами `0700`.
  - [x] Записывать private key с правами `0600` и certificate chain с правами `0644`.
  - [x] Выполнять fsync временных файлов и каталога до атомарного rename.
  - [x] Публиковать новую TLS-ревизию только после криптографической проверки.
  - [x] Хранить предыдущую рабочую TLS-ревизию до подтверждения reload endpoint.
  - [x] Не менять активную ревизию при неудачном issue или renew.

- [x] Интегрировать TLS-ревизию с `hosts.toml` и supervisor
  - [x] Передавать в renderer `hosts.toml` только пути активной проверенной TLS-ревизии.
  - [x] Применять обновлённый `hosts.toml` через общий атомарный apply-механизм.
  - [x] Отправлять SIGHUP после успешной публикации новой TLS-ревизии.
  - [x] Проверять доступность endpoint после SIGHUP в ограниченном timeout.
  - [x] Возвращать предыдущую TLS-ревизию и повторять SIGHUP, если проверка не прошла.

- [x] Реализовать renewal scheduler
  - [x] Вычислять окно renewal от not-after и настраиваемого запаса времени.
  - [x] Добавить jitter к плановым попыткам.
  - [x] Использовать exponential backoff с верхней границей при ошибках.
  - [x] Не прекращать работу endpoint, пока текущий сертификат валиден.
  - [x] Помечать readiness как degraded при приближении expiry после повторных неудач.
  - [x] Останавливать scheduler и дожидаться активной ACME-операции при SIGTERM.

- [x] Добавить manual certificate fallback
  - [x] Принимать PEM chain и private key только через авторизованный внутренний service method.
  - [x] Применять те же криптографические проверки, permissions, атомарную публикацию и rollback.
  - [x] Отключать ACME scheduler для manual-режима.
  - [x] Сохранять в SQLite только метаданные и пути, не PEM-содержимое.

- [x] Покрыть управление сертификатами автоматическими проверками
  - [x] Добавить unit-тесты переходов состояния, renewal window, jitter, backoff и валидации PEM.
  - [x] Добавить integration-тесты HTTP-01 с локальным ACME test server или Pebble.
  - [x] Проверить issue и renewal на staging-контуре без обращения к production Let's Encrypt.
  - [x] Добавить fault-injection тесты на network timeout, invalid chain, mismatched key, disk full, crash между fsync и rename, ошибку SIGHUP и неудачный rollback.
  - [x] Проверить permissions всех account key, private key и certificate files в Linux-контейнере.
  - [x] Проверить, что логи, health и apply history не содержат private key, account key и challenge token.
