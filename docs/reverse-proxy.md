# Admin UI reverse proxy boundary

Production access to the administrator UI goes through a dedicated TLS reverse
proxy. The example deliberately does **not** proxy TrustTunnel VPN traffic.
Because both protocols normally use TCP 443, the UI example requires a separate
host IP and DNS name; set `TT_ADMIN_BIND_IP` to that address and replace
`admin.example.net` in `deploy/nginx-admin.conf`.

```sh
docker compose -f docker-compose.yml \
  -f docker-compose.reverse-proxy.yml config
docker compose -f docker-compose.yml \
  -f docker-compose.reverse-proxy.yml up -d
```

The proxy has the fixed address `172.31.250.2` on the internal `/29` network,
and the controller trusts exactly `172.31.250.2/32`. Nginx overwrites, rather
than appends, `X-Forwarded-For` and sets `X-Forwarded-Proto: https`; requests
from every other peer have forwarded headers ignored. The proxy receives static
certificate/key bind mounts and no Docker socket, service-discovery privilege,
host network, or access to the controller data volume.
