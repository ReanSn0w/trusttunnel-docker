# Connection profiles and DPI experiments

`Connection` (`/connection`) stores defaults for future exports. Save, then export
again from `Users`. Existing imported profiles are not remotely changed, and
these settings do not restart the endpoint or change firewall/listener rules.

The public address defaults to the VPN certificate hostname on **443**, not the
container's internal 8443. Set an explicit `host:port` for different mappings
(local smoke: `127.0.0.1:18443`). The certificate hostname remains unchanged.

## What the controls actually do

- HTTP/2 uses TCP; HTTP/3 uses QUIC/UDP. Test them separately: either can be
  affected by a network policy.
- Anti-DPI is implemented **in the client**. The inspected native implementation
  rate-limits the initial TLS write to one byte, with a 25 ms bucket interval,
  then removes the limit. This changes ClientHello delivery; it does not hide
  the destination IP or guarantee bypass. The controller exposes it for HTTP/2.
- TLS profile changes the ClientHello fingerprint. Available profiles are
  `chrome`, `safari`, `firefox`, `okhttp`, `openssl`, and `default`.
- Post-quantum exchange stays enabled by default. The smaller-ClientHello preset
  disables it for a controlled comparison, without disabling conventional TLS
  or certificate validation. This loses post-quantum protection; not all TLS
  profiles/builds necessarily change size by the same amount.
- IPv6 controls whether the endpoint can carry IPv6 traffic.

TrustTunnel carries tunnel traffic inside HTTP/2 or HTTP/3 over TLS. Looking like
HTTPS is not invisibility: IP, visible handshake metadata and traffic patterns
can still be classified. A random third-party SNI is not a working substitute
for a matching certificate. TLS random-prefix admission rules are not exposed
here: they require coordinated server/client configuration and do not repair a
ClientHello that never fully reaches the server.

## Exports and mobile limitation

`TOML` downloads the endpoint section; `CLI TOML` downloads a complete native
configuration with TUN listener and top-level `post_quantum_group_enabled`.
The released native CLI [v1.1.7](https://github.com/TrustTunnel/TrustTunnelClient/releases/tag/v1.1.7)
documents `post_quantum_group_enabled`, `anti_dpi`, `upstream_protocol`, IPv6,
credentials and certificate fields, but its tagged
[configuration reference](https://github.com/TrustTunnel/TrustTunnelClient/blob/v1.1.7/trusttunnel/README.md)
does not contain `tls_profile`. The field appears in the
[unreleased changelog](https://github.com/TrustTunnel/TrustTunnelClient/blob/def663d06e7d6e99e024702ac45e0cad6749e32d/CHANGELOG.md)
and source commit `def663d`. No released minimum version for the complete CLI
TOML has been verified. Use a compatible source build for TLS fingerprint
selection; the other settings can be checked against v1.1.7. To run a compatible
native client:

```sh
sudo trusttunnel_client -c trusttunnel-client.toml
```

The complete profile changes system routes/DNS while running; do not test it
over your only remote-management connection. Downloads and links contain VPN
credentials: keep them private. Original credentials, certificate and unknown
endpoint fields are preserved. No verification-bypass option is introduced.
The pinned endpoint v1.1.0 exporter was checked with both self-signed and
provided PEM input: the certificate reached the TOML and deeplink alongside
the original username/password and explicit external port 443. If a client
pins the old self-signed or provided certificate, export and reimport the
profile after rotation; an existing imported profile is not updated remotely.

The browser launch control is a direct `tt://` link and needs an installed
system handler. Its anchor was checked in the browser without a QR scan; an
actual mobile app launch was not available in this environment.

The official TLV deeplink supports protocol, Anti-DPI and IPv6, but has no tags
for TLS profile or post-quantum exchange. More importantly, the inspected
Flutter application discards `antiDpi` when converting an imported link into
`ServerData`; its native configuration construction also omits that field.
Therefore the WebUI cannot activate Anti-DPI in that mobile build. The UI warns
about this; a compatible/fixed client is required. The browser launch button
opens `tt://` directly and does not require a QR scanner.

This is a source-level finding at the commits below, not a claim that every
past/future App Store binary has been tested. The iOS client version reported
in the incident was 1.2.0; no patched iOS binary was built or installed here.

## Diagnostic sequence

1. Keep hostname, address, account and certificate constant. Compare direct
   connection with the same profile inside another VPN.
2. On a compatible client, compare baseline HTTP/2, then Anti-DPI, then the
   smaller ClientHello, changing one variable at a time. Test QUIC separately.
3. Capture a complete attempt, not just the first 30 packets. Capture on one
   interface to avoid counting bridge/veth duplicates. Include TCP and UDP.
4. Compare TCP sequence ranges and TLS record length before blaming auth or
   application configuration. In the reported trace, the declared first TLS
   record was 1828 bytes including its header; only 1424 bytes arrived.
5. VPN success indicates a path-dependent problem; it alone does not identify
   TSPU versus another middlebox, routing or MTU problem. No live bypass success
   is asserted by this controller change.

## Reproducible local connection check (2026-09-25)

`scripts/test-local-connection.sh` uses the controller image with the pinned
TrustTunnel endpoint v1.1.0, the official Linux x86_64 CLI v1.1.7, and a
disposable Docker network. It changes only the named profile setting between
runs. Each client reaches a private HTTP test service through its SOCKS listener
and the VPN endpoint; the script verifies the response body. The test endpoint
sets `allow_private_network_connections = true` solely to reach that private
service. The production endpoint retains the upstream default of `false`.

Run with a locally built controller image and the extracted official CLI binary:

```sh
IMAGE=trusttunnel-controller:local \
CLIENT_BINARY=/absolute/path/to/trusttunnel_client \
PLATFORM=linux/amd64 ./scripts/test-local-connection.sh
```

The script captures each complete attempt on the endpoint container's `eth0`
only, with TCP and UDP port 8443. It checks for captured frames, reconstructs
the first TLS record header across the Anti-DPI split, and counts UDP packets.
One verified run produced:

| Profile | HTTP response | First TLS record payload | UDP packets to endpoint |
| --- | --- | ---: | ---: |
| HTTP/2 baseline | pass | 1758 bytes | 0 |
| HTTP/2 + Anti-DPI | pass | 1758 bytes | 0 |
| HTTP/2, post-quantum off | pass | 512 bytes | 0 |
| HTTP/3 (QUIC) | pass | none | 17 |

The Anti-DPI trace split the first TLS record across TCP writes. In this run
its record length matched baseline; a repeat measured 1822 bytes for Anti-DPI
and 1758 for baseline. Another local run measured 600 bytes for the
post-quantum-off record. ClientHello size varies between attempts, so a single
byte count is not a fixed client contract or proof that Anti-DPI changes only
packet boundaries. These measurements show a smaller ClientHello with
post-quantum disabled in this setup and a successful QUIC tunnel. They do not
establish which variant works on the user's affected network. No capture,
packet-loss comparison, mobile app test, or bypass result from that network is
available here. The released CLI lacks `tls_profile`, so the runtime probe
omits that unsupported field; the exported complete CLI TOML still requires a
compatible source build for TLS profile selection.

## Inspected primary sources (2026-09-24)

- [Native anti-DPI write handling](https://github.com/TrustTunnel/TrustTunnelClient/blob/def663d06e7d6e99e024702ac45e0cad6749e32d/net/src/tcp_socket.cpp),
  [split constants](https://github.com/TrustTunnel/TrustTunnelClient/blob/def663d06e7d6e99e024702ac45e0cad6749e32d/net/include/net/utils.h).
- [Native configuration](https://github.com/TrustTunnel/TrustTunnelClient/blob/def663d06e7d6e99e024702ac45e0cad6749e32d/trusttunnel/README.md).
- [Official deeplink format](https://github.com/TrustTunnel/TrustTunnel/blob/master/DEEP_LINK.md).
- [Flutter link import](https://github.com/TrustTunnel/TrustTunnelFlutterClient/blob/cca55ee8f8811ba651488e89f3af09a2244615c5/lib/data/datasources/local_sources/server_datasource_impl.dart),
  [native configuration assembly](https://github.com/TrustTunnel/TrustTunnelFlutterClient/blob/cca55ee8f8811ba651488e89f3af09a2244615c5/lib/data/datasources/native_sources/vpn_datasource_impl.dart).
