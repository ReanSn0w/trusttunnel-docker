# Архитектура TrustTunnel Controller

Контроллер — единственный владелец изменяемого состояния инсталляции и процесс
PID 1 контейнера. Официальный `trusttunnel_endpoint` остаётся владельцем
протокола VPN; контроллер не реализует и не модифицирует его wire format.

## Жизненный цикл

1. Открыть SQLite, применить однонаправленные миграции и выполнить
   идемпотентный bootstrap.
2. Загрузить доменное состояние и проверить его до любой записи на диск.
3. Детерминированно отрендерить TOML в staging-каталог, проверить набор и
   атомарно опубликовать ревизию.
4. Запустить endpoint с явными аргументами без shell и дождаться readiness.
5. Обслуживать probes, UI и операции service layer, сериализуя apply.
6. При SIGTERM/SIGINT прекратить новые мутации, отменить фоновые операции,
   корректно остановить endpoint и дождаться дочерних процессов.

Изменение `vpn.toml`, `credentials.toml` или `rules.toml` требует controlled
restart. Смена только путей проверенной TLS-цепочки в `hosts.toml` применяется
через SIGHUP с проверкой readiness и rollback при неуспехе.

## Границы пакетов

- `domain`: типы и инварианты без HTTP, SQL и процессов.
- `persistence`: транзакции, миграции и единственный writer SQLite.
- `config`: валидация, TOML renderer, атомарные ревизии и rollback.
- `supervisor`: жизненный цикл дочернего endpoint и crash-loop protection.
- `endpointcli`: ограниченный экспорт официальным CLI.
- `metrics`: bounded-загрузка и разбор разрешённых Prometheus-серий.
- `probe`: liveness/readiness без секретов.
- `service`: единственная граница изменяющих операций для UI и TLS.

HTTP handlers не импортируют SQL repository, renderer или supervisor напрямую.

## Основные интерфейсы

```go
type Repository interface {
    Snapshot(context.Context) (domain.Snapshot, error)
    Apply(context.Context, domain.Change) (domain.Revision, error)
    RecordEvent(context.Context, domain.ApplyEvent) error
}
type Renderer interface { Render(context.Context, domain.Snapshot) (config.Files, error) }
type Validator interface { Validate(domain.Snapshot) error }
type ProcessSupervisor interface {
    Start(context.Context, string) error
    Restart(context.Context, string) error
    Reload(context.Context) error
    Stop(context.Context) error
    Status() domain.EndpointStatus
}
type EndpointCLI interface { Export(context.Context, domain.User, string) (domain.ClientConfig, error) }
type MetricsReader interface { Read(context.Context) (domain.EndpointMetrics, error) }
type EventLog interface { Append(domain.Event); Recent(int) []domain.Event }
```

Apply удерживает mutex на всём пути `DB transaction → staging → validation →
publish → restart/reload → readiness`. При ошибке файловая ревизия и состояние
SQLite возвращаются к последней подтверждённой паре. История получает только
санитизированную причину, без credentials, session token, ACME token, private
key и клиентского deeplink.
