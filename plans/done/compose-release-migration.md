---
Название: "Миграция Compose и выпуск single-container образа"
Сложность: hard
Важность: 4
Дата завершения: 2026-09-23
---

## Что мы делаем?

Мигрируем существующие `docker-compose.yml` и `docker-compose.local.yml` с prebuilt endpoint на итоговый multi-arch single-container образ с Go-контроллером. План охватывает минимальный production-запуск, безопасный local override, persistent volumes, порты, reverse proxy boundary, multi-arch release, SBOM/provenance, бэкап, upgrade и rollback. Реализация начинается только после готовности ядра, ACME и Web UI.

## Для чего мы делаем?

Текущие Compose-файлы уже дают понятный минимальный запуск официального endpoint v1.1.0 и безопасный smoke-вариант на `127.0.0.1:8443`. Новый образ меняет layout данных, lifecycle процесса, владельца сертификатов и способ администрирования, поэтому его нельзя подменить без явной миграции и возможности вернуться назад.

## План

- [x] Зафиксировать release-контракт образа
  - [x] Задать имя image, семантику immutable tags и правило привязки к Git commit.
  - [x] Задать матрицу `linux/amd64` и `linux/arm64`.
  - [x] Зафиксировать в metadata версию Go-контроллера, commit, версию endpoint и SHA-256 официального release-архива.
  - [x] Не использовать mutable `latest` в production-примере запуска.

- [x] Настроить воспроизводимую multi-arch сборку
  - [x] Собирать Go-бинарник и runtime image для каждой архитектуры без эмуляции в release pipeline, где это возможно.
  - [x] Проверять SHA-256 официального endpoint до копирования в runtime-слой.
  - [x] Пиновать base image по digest.
  - [x] Генерировать SBOM для каждой архитектуры.
  - [x] Публиковать build provenance и подпись image manifest.
  - [x] Блокировать публикацию при провале vulnerability scan по согласованной severity policy.

- [x] Спроектировать persistent data layout и перенос текущего volume
  - [x] Задать стабильные каталоги для SQLite, config revisions, TLS, ACME account и ограниченных логов.
  - [x] Описать mapping текущих `vpn.toml`, `hosts.toml`, `credentials.toml`, `rules.toml` и `certs/` из `trusttunnel_endpoint_data`.
  - [x] Определить, как импортируется первичный VPN-пользователь без вывода пароля в логи.
  - [x] Сделать migration одноразовой, идемпотентной и отказоустойчивой к частичному переносу.
  - [x] Не удалять старый volume автоматически.
  - [x] Запретить запуск двух endpoint на одних и тех же persistent-данных.

- [x] Обновить минимальный production Compose
  - [x] Заменить сборку `Dockerfile.prebuilt` на итоговый image с фиксированным version tag или digest.
  - [x] Сохранить один основной service и один persistent volume.
  - [x] Опубликовать 443/TCP для HTTPS/HTTP2 и 443/UDP для QUIC/HTTP3.
  - [x] Опубликовать 80/TCP только для ACME HTTP-01.
  - [x] Не публиковать admin UI на внешний интерфейс по умолчанию.
  - [x] Добавить internal network для подключения опционального reverse proxy к UI.
  - [x] Оставить в Compose короткие русские комментарии только для подставляемых значений, портов, UI boundary и volume.
  - [x] Не добавлять Docker socket, privileged mode, host networking, root SSH, `NET_ADMIN` и `NET_RAW`.

- [x] Обновить безопасный local Compose override
  - [x] Сохранить привязку VPN-портов только к `127.0.0.1` на свободных высоких TCP/UDP-портах.
  - [x] Привязать admin UI только к `127.0.0.1` на отдельном высоком TCP-порту.
  - [x] Не публиковать 80/TCP в локальном режиме без теста ACME HTTP-01.
  - [x] Перевести ACME в staging для явного локального ACME-теста.
  - [x] Предусмотреть отдельный тестовый volume, чтобы smoke-запуск не мигрировал production-данные.
  - [x] Обновить `.env.example` только после фиксации итогового runtime-контракта.

- [x] Описать reverse proxy boundary для admin UI
  - [x] Привести минимальный пример reverse proxy с TLS, отдельным UI hostname и без проксирования VPN-трафика.
  - [x] Ограничить trusted proxy addresses точными Compose-подсетями.
  - [x] Передавать `X-Forwarded-Proto` и client IP только от доверенного reverse proxy.
  - [x] Не монтировать в reverse proxy Docker socket ради service discovery в базовом примере.

- [x] Создать процедуры бэкапа, upgrade и rollback
  - [x] Делать SQLite online backup штатным backup API или корректной checkpoint-процедурой.
  - [x] Включать в бэкап SQLite, config revisions, TLS/ACME-данные и manifest с версиями.
  - [x] Защитить бэкап как секрет, потому что он содержит VPN credentials и private keys.
  - [x] Проверять backup до upgrade и не начинать миграцию при неудаче.
  - [x] Пиновать предыдущий image digest и сохранять его до завершения smoke-проверок.
  - [x] Описать rollback image и данных с явным предупреждением о необратимых SQLite-миграциях.
  - [x] Проверить восстановление бэкапа на отдельном тестовом volume.

- [x] Обновить эксплуатационную документацию
  - [x] Описать минимальный первый запус с доменом, ACME email, bootstrap-паролем и проверкой DNS/портов.
  - [x] Описать локальный smoke-запуск без публикации UI и VPN на внешних интерфейсах.
  - [x] Описать отдельный reverse proxy как единственный production-путь к admin UI.
  - [x] Описать backup, restore, upgrade, rollback и ротацию admin-пароля.
  - [x] Описать удаление контейнера отдельно от удаления persistent volume.

- [x] Провести release-проверки
  - [x] Прогнать `docker compose config` для production и local override с placeholder-секретами.
  - [x] Прогнать smoke-запуск обеих архитектур с проверкой PID 1, child endpoint, TCP/UDP listener'ов, health, readiness и UI login.
  - [x] Проверить graceful shutdown по `docker stop` и отсутствие zombie-процессов.
  - [x] Провести миграцию копии текущего `trusttunnel_endpoint_data` и сверить пользователей, hostname, сертификат и клиентский deeplink.
  - [x] Провести upgrade между двумя release-версиями на копии production-данных.
  - [x] Провести rollback к предыдущему image и восстановленному backup на копии данных.
  - [x] Сверить image digest, SBOM, provenance, подпись и встроенные версии перед публикацией release.
