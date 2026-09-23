---
Название: "Миграция Compose и выпуск single-container образа"
Сложность: hard
Важность: 4
---

## Что мы делаем?

Мигрируем существующие `docker-compose.yml` и `docker-compose.local.yml` с prebuilt endpoint на итоговый multi-arch single-container образ с Go-контроллером. План охватывает минимальный production-запуск, безопасный local override, persistent volumes, порты, reverse proxy boundary, multi-arch release, SBOM/provenance, бэкап, upgrade и rollback. Реализация начинается только после готовности ядра, ACME и Web UI.

## Для чего мы делаем?

Текущие Compose-файлы уже дают понятный минимальный запуск официального endpoint v1.1.0 и безопасный smoke-вариант на `127.0.0.1:8443`. Новый образ меняет layout данных, lifecycle процесса, владельца сертификатов и способ администрирования, поэтому его нельзя подменить без явной миграции и возможности вернуться назад.

## План

- [ ] Зафиксировать release-контракт образа
  - [ ] Задать имя image, семантику immutable tags и правило привязки к Git commit.
  - [ ] Задать матрицу `linux/amd64` и `linux/arm64`.
  - [ ] Зафиксировать в metadata версию Go-контроллера, commit, версию endpoint и SHA-256 официального release-архива.
  - [ ] Не использовать mutable `latest` в production-примере запуска.

- [ ] Настроить воспроизводимую multi-arch сборку
  - [ ] Собирать Go-бинарник и runtime image для каждой архитектуры без эмуляции в release pipeline, где это возможно.
  - [ ] Проверять SHA-256 официального endpoint до копирования в runtime-слой.
  - [ ] Пиновать base image по digest.
  - [ ] Генерировать SBOM для каждой архитектуры.
  - [ ] Публиковать build provenance и подпись image manifest.
  - [ ] Блокировать публикацию при провале vulnerability scan по согласованной severity policy.

- [ ] Спроектировать persistent data layout и перенос текущего volume
  - [ ] Задать стабильные каталоги для SQLite, config revisions, TLS, ACME account и ограниченных логов.
  - [ ] Описать mapping текущих `vpn.toml`, `hosts.toml`, `credentials.toml`, `rules.toml` и `certs/` из `trusttunnel_endpoint_data`.
  - [ ] Определить, как импортируется первичный VPN-пользователь без вывода пароля в логи.
  - [ ] Сделать migration одноразовой, идемпотентной и отказоустойчивой к частичному переносу.
  - [ ] Не удалять старый volume автоматически.
  - [ ] Запретить запуск двух endpoint на одних и тех же persistent-данных.

- [ ] Обновить минимальный production Compose
  - [ ] Заменить сборку `Dockerfile.prebuilt` на итоговый image с фиксированным version tag или digest.
  - [ ] Сохранить один основной service и один persistent volume.
  - [ ] Опубликовать 443/TCP для HTTPS/HTTP2 и 443/UDP для QUIC/HTTP3.
  - [ ] Опубликовать 80/TCP только для ACME HTTP-01.
  - [ ] Не публиковать admin UI на внешний интерфейс по умолчанию.
  - [ ] Добавить internal network для подключения опционального reverse proxy к UI.
  - [ ] Оставить в Compose короткие русские комментарии только для подставляемых значений, портов, UI boundary и volume.
  - [ ] Не добавлять Docker socket, privileged mode, host networking, root SSH, `NET_ADMIN` и `NET_RAW`.

- [ ] Обновить безопасный local Compose override
  - [ ] Сохранить привязку VPN-портов только к `127.0.0.1` на свободных высоких TCP/UDP-портах.
  - [ ] Привязать admin UI только к `127.0.0.1` на отдельном высоком TCP-порту.
  - [ ] Не публиковать 80/TCP в локальном режиме без теста ACME HTTP-01.
  - [ ] Перевести ACME в staging для явного локального ACME-теста.
  - [ ] Предусмотреть отдельный тестовый volume, чтобы smoke-запуск не мигрировал production-данные.
  - [ ] Обновить `.env.example` только после фиксации итогового runtime-контракта.

- [ ] Описать reverse proxy boundary для admin UI
  - [ ] Привести минимальный пример reverse proxy с TLS, отдельным UI hostname и без проксирования VPN-трафика.
  - [ ] Ограничить trusted proxy addresses точными Compose-подсетями.
  - [ ] Передавать `X-Forwarded-Proto` и client IP только от доверенного reverse proxy.
  - [ ] Не монтировать в reverse proxy Docker socket ради service discovery в базовом примере.

- [ ] Создать процедуры бэкапа, upgrade и rollback
  - [ ] Делать SQLite online backup штатным backup API или корректной checkpoint-процедурой.
  - [ ] Включать в бэкап SQLite, config revisions, TLS/ACME-данные и manifest с версиями.
  - [ ] Защитить бэкап как секрет, потому что он содержит VPN credentials и private keys.
  - [ ] Проверять backup до upgrade и не начинать миграцию при неудаче.
  - [ ] Пиновать предыдущий image digest и сохранять его до завершения smoke-проверок.
  - [ ] Описать rollback image и данных с явным предупреждением о необратимых SQLite-миграциях.
  - [ ] Проверить восстановление бэкапа на отдельном тестовом volume.

- [ ] Обновить эксплуатационную документацию
  - [ ] Описать минимальный первый запус с доменом, ACME email, bootstrap-паролем и проверкой DNS/портов.
  - [ ] Описать локальный smoke-запуск без публикации UI и VPN на внешних интерфейсах.
  - [ ] Описать отдельный reverse proxy как единственный production-путь к admin UI.
  - [ ] Описать backup, restore, upgrade, rollback и ротацию admin-пароля.
  - [ ] Описать удаление контейнера отдельно от удаления persistent volume.

- [ ] Провести release-проверки
  - [ ] Прогнать `docker compose config` для production и local override с placeholder-секретами.
  - [ ] Прогнать smoke-запуск обеих архитектур с проверкой PID 1, child endpoint, TCP/UDP listener'ов, health, readiness и UI login.
  - [ ] Проверить graceful shutdown по `docker stop` и отсутствие zombie-процессов.
  - [ ] Провести миграцию копии текущего `trusttunnel_endpoint_data` и сверить пользователей, hostname, сертификат и клиентский deeplink.
  - [ ] Провести upgrade между двумя release-версиями на копии production-данных.
  - [ ] Провести rollback к предыдущему image и восстановленному backup на копии данных.
  - [ ] Сверить image digest, SBOM, provenance, подпись и встроенные версии перед публикацией release.
