# TLS lifecycle and MVP boundary

Автоматический режим MVP использует только ACME HTTP-01. DNS-01 и credentials
DNS-провайдеров в модель, формы и persistence не входят. Ручной режим принимает
только готовую PEM-цепочку и соответствующий private key через внутренний
service method; внешний certbot не запускается.

Состояния сертификата:

- `unconfigured` → `issuing` после валидированных hostname/email;
- `issuing` → `active` после проверки и публикации, либо → `degraded` при ошибке;
- `active` → `renewing` внутри renewal window;
- `renewing` → `active` после reload, либо → `degraded` с сохранением старой ревизии;
- `degraded` → `renewing` при следующей попытке либо → `active`, пока старая цепочка подтверждённо рабочая;
- любое настроенное состояние → `manual` только после проверки и атомарной публикации импортированного PEM;
- `manual` → `issuing` только явным переключением обратно в ACME.

Issue, renew и manual import используют ту же apply-блокировку, что и конфиги.
Сначала создаётся TLS-ревизия, затем `hosts.toml`, затем SIGHUP и bounded readiness
check. Только после успеха новая пара ревизий становится активной. Ошибка на
любом этапе возвращает TLS и config pointers и пишет санитизированное событие.

История и логи могут содержать hostname, issuer, serial, fingerprint, сроки и
класс ошибки. Private key, account key, HTTP-01 token/key authorization и PEM
содержимое в них запрещены.
