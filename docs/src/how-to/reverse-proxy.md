# Run behind a reverse proxy with TLS

nanobom speaks plain HTTP. Put a reverse proxy in front of it to terminate TLS, and tell nanobom
the address users reach it at:

```sh
NANOBOM_PUBLIC_URL=https://nanobom.example.org
NANOBOM_TRUST_FORWARDED_HEADERS=true
```

Bind nanobom to the loopback interface or a private network
(`NANOBOM_LISTEN_ADDRESS=127.0.0.1:8080` on the same host),
so the proxy is the only way in. Only set `NANOBOM_TRUST_FORWARDED_HEADERS` when that is the case:
a client talking to nanobom directly could otherwise choose its own address and escape sign-in
rate limiting.

What the proxy must get right:

| | Why |
| --- | --- |
| **Serve nanobom at the root of a host name** | Pages and redirects use absolute paths (`/login`, `/organizations/…`); a sub-path such as `https://example.org/nanobom/` is not supported. |
| **The public URL matches the browser's address bar** | Form submissions whose `Origin` differs from `NANOBOM_PUBLIC_URL` are refused as cross-site (`403 cross-site request refused`); cookies are `Secure` when it is `https`; OpenID Connect redirects to it. |
| **Request bodies up to `NANOBOM_MAXIMUM_SBOM_SIZE`** (16 MiB) | nginx accepts 1 MiB by default and answers `413` itself. |
| **Responses that take up to `NANOBOM_UPLOAD_WAIT_SECONDS`** (300 s) | Uploads with `wait` or `fail_on` hold the request until the evaluation; many proxies give up after 60 seconds with a `504`. |
| **Client addresses in `X-Forwarded-For`** | Sign-in rate limiting is per client address; behind a proxy, every request otherwise comes from the proxy. The proxy must **replace** the header, not append to what the client sent. |
| **`/metrics` kept internal** | It needs no authentication; it reveals only instance-wide counts, but there is no reason to publish them. |

HSTS is left to the proxy: nanobom does not send it.

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name nanobom.example.org;

    ssl_certificate     /etc/letsencrypt/live/nanobom.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nanobom.example.org/privkey.pem;

    # NANOBOM_MAXIMUM_SBOM_SIZE is 16 MiB by default.
    client_max_body_size 16m;

    proxy_set_header Host              $host;
    # Replaces whatever the client sent, so it cannot pick its own address.
    proxy_set_header X-Forwarded-For   $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }

    # Uploads that wait for their evaluation (NANOBOM_UPLOAD_WAIT_SECONDS is 300 by default).
    location /api/organizations/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_read_timeout 330s;
    }

    location = /metrics {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://127.0.0.1:8080;
    }
}

server {
    listen 80;
    server_name nanobom.example.org;
    return 301 https://$host$request_uri;
}
```

## Caddy

Caddy obtains and renews the certificate, replaces `X-Forwarded-For` with the client's address,
and has no body size limit or response timeout by default:

```caddy
nanobom.example.org {
    @external_metrics {
        path /metrics
        not remote_ip 10.0.0.0/8
    }
    respond @external_metrics 403
    reverse_proxy 127.0.0.1:8080
}
```

## Traefik

With Docker Compose, next to a Traefik instance whose `websecure` entry point terminates TLS:

```yaml
services:
  nanobom:
    image: ghcr.io/alixanneraud/nanobom:latest
    restart: unless-stopped
    volumes:
      - nanobom-data:/data
    environment:
      NANOBOM_PUBLIC_URL: https://nanobom.example.org
      NANOBOM_TRUST_FORWARDED_HEADERS: "true"
    labels:
      traefik.enable: "true"
      traefik.http.routers.nanobom.rule: Host(`nanobom.example.org`)
      traefik.http.routers.nanobom.entrypoints: websecure
      traefik.http.routers.nanobom.tls.certresolver: letsencrypt
      traefik.http.services.nanobom.loadbalancer.server.port: "8080"

volumes:
  nanobom-data:
```

No port is published: Traefik reaches the container on the Docker network. Traefik discards the
`X-Forwarded-*` headers of untrusted clients and sets its own. Traefik 3 limits reading a request
to 60 seconds by default (`respondingTimeouts.readTimeout`); waiting uploads hold their request
longer, so raise it on the entry point as a precaution, in Traefik's static configuration:

```yaml
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: 330s
```

`/metrics` is reachable through this router; add a router with a higher priority for
`Path(`/metrics`)` and an `ipAllowList` middleware, or scrape the container directly on the
Docker network instead.

## Without a proxy

For a test instance on a private network, nanobom can be reached directly on port 8080. Keep
`NANOBOM_PUBLIC_URL` at the address you type in the browser (`http://192.168.1.20:8080`):
otherwise every form submission is refused as cross-site.
