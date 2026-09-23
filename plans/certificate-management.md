---
Название: "Управление TLS-сертификатами TrustTunnel"
Сложность: hard
Важность: 2
---

## Что мы делаем?

Добавляем в Go-контроллер управление TLS: выпуск и продление Let's Encrypt через `go-acme/lego`, HTTP-01 на 80/TCP, staging-режим, атомарное хранение PEM, безопасное продление, rollback и SIGHUP endpoint. DNS-01 не входит в MVP; ручной сертификат поддерживается как ограниченный fallback.

## Для чего мы делаем?

Текущий shell-entrypoint может получить сертификат при первичной настройке, но не обеспечивает контролируемый renewal и безопасный rollback. Контроллер должен сам удерживать валидную TLS-цепочку, не подменять её при ошибке ACME и обновлять endpoint без разрыва активных сессий.

## План

- [ ] Определить TLS domain model и границы MVP
  - [ ] Описать состояния `unconfigured`, `issuing`, `active`, `renewing`, `degraded` и `manual` с однозначными переходами.
  - [ ] Зафиксировать HTTP-01 как единственный автоматический challenge MVP.
  - [ ] Отложить DNS-01 и провайдерские credentials до отдельного расширения.
  - [ ] Ограничить manual fallback импортом PEM-цепочки и закрытого ключа без внешнего certbot.
  - [ ] Увязать TLS-операции с apply-блокировкой и историей ревизий из ядра контроллера.

- [ ] Добавить persistence ACME-аккаунта и метаданных сертификата
  - [ ] Хранить ACME directory URL, account email, registration URI, статус, timestamps и последнюю ошибку в SQLite.
  - [ ] Хранить ACME account key в persistent data directory с правами `0600`.
  - [ ] Хранить serial, issuer, SAN, not-before, not-after, fingerprint и пути активной TLS-ревизии.
  - [ ] Не сохранять private key, ACME account key или challenge token в application logs и apply history.

- [ ] Интегрировать `go-acme/lego`
  - [ ] Зафиксировать совместимую версию lego в Go module.
  - [ ] Реализовать adapter ACME client, чтобы тесты не зависели от production Let's Encrypt.
  - [ ] Создавать или восстанавливать ACME account идемпотентно.
  - [ ] Разделить production и staging directory URL явным типизированным режимом.
  - [ ] Отклонять непубличные hostname, IP вместо DNS-имени и невалидный email до вызова ACME.

- [ ] Реализовать HTTP-01 challenge listener
  - [ ] Открывать выделенный listener на 80/TCP только для challenge и ограниченных redirect/diagnostic ответов.
  - [ ] Обслуживать только текущие challenge token по точному path.
  - [ ] Ограничить header size, request timeout, idle timeout и число параллельных challenge-запросов.
  - [ ] Удалять challenge state после завершения или отмены ACME-операции.
  - [ ] Корректно завершать listener при SIGTERM контроллера.

- [ ] Реализовать первичный выпуск сертификата
  - [ ] Сериализовать issue/renew для одного hostname на контроллер.
  - [ ] Ограничить всю ACME-операцию context timeout и корректно отменять её при shutdown.
  - [ ] Проверять цепочку, SAN, сроки, соответствие private key и PEM encoding до публикации.
  - [ ] Отклонять сертификат от staging CA при production-режиме.
  - [ ] Записывать понятную ошибку в apply history без ACME token и key material.

- [ ] Добавить атомарное хранение PEM и TLS rollback
  - [ ] Создавать каталог TLS-ревизии с правами `0700`.
  - [ ] Записывать private key с правами `0600` и certificate chain с правами `0644`.
  - [ ] Выполнять fsync временных файлов и каталога до атомарного rename.
  - [ ] Публиковать новую TLS-ревизию только после криптографической проверки.
  - [ ] Хранить предыдущую рабочую TLS-ревизию до подтверждения reload endpoint.
  - [ ] Не менять активную ревизию при неудачном issue или renew.

- [ ] Интегрировать TLS-ревизию с `hosts.toml` и supervisor
  - [ ] Передавать в renderer `hosts.toml` только пути активной проверенной TLS-ревизии.
  - [ ] Применять обновлённый `hosts.toml` через общий атомарный apply-механизм.
  - [ ] Отправлять SIGHUP после успешной публикации новой TLS-ревизии.
  - [ ] Проверять доступность endpoint после SIGHUP в ограниченном timeout.
  - [ ] Возвращать предыдущую TLS-ревизию и повторять SIGHUP, если проверка не прошла.

- [ ] Реализовать renewal scheduler
  - [ ] Вычислять окно renewal от not-after и настраиваемого запаса времени.
  - [ ] Добавить jitter к плановым попыткам.
  - [ ] Использовать exponential backoff с верхней границей при ошибках.
  - [ ] Не прекращать работу endpoint, пока текущий сертификат валиден.
  - [ ] Помечать readiness как degraded при приближении expiry после повторных неудач.
  - [ ] Останавливать scheduler и дожидаться активной ACME-операции при SIGTERM.

- [ ] Добавить manual certificate fallback
  - [ ] Принимать PEM chain и private key только через авторизованный внутренний service method.
  - [ ] Применять те же криптографические проверки, permissions, атомарную публикацию и rollback.
  - [ ] Отключать ACME scheduler для manual-режима.
  - [ ] Сохранять в SQLite только метаданные и пути, не PEM-содержимое.

- [ ] Покрыть управление сертификатами автоматическими проверками
  - [ ] Добавить unit-тесты переходов состояния, renewal window, jitter, backoff и валидации PEM.
  - [ ] Добавить integration-тесты HTTP-01 с локальным ACME test server или Pebble.
  - [ ] Проверить issue и renewal на staging-контуре без обращения к production Let's Encrypt.
  - [ ] Добавить fault-injection тесты на network timeout, invalid chain, mismatched key, disk full, crash между fsync и rename, ошибку SIGHUP и неудачный rollback.
  - [ ] Проверить permissions всех account key, private key и certificate files в Linux-контейнере.
  - [ ] Проверить, что логи, health и apply history не содержат private key, account key и challenge token.
