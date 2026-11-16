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
| **Request bodies of 24 MiB** | Native uploads are at most `NANOBOM_MAXIMUM_SBOM_SIZE` (16 MiB), but [Dependency-Track clients](dependency-track-clients.md) send the SBOM base64-encoded, a third larger. nginx accepts 1 MiB by default and answers `413` itself. Scale the limit with `NANOBOM_MAXIMUM_SBOM_SIZE` (one and a half times it). |
| **Responses that take up to `NANOBOM_UPLOAD_WAIT_SECONDS`** (300 s) | Uploads with `wait` or `fail_on` hold the request until the evaluation; many proxies give up after 60 seconds with a `504`. |
| **Client addresses in `X-Forwarded-For`** | Sign-in rate limiting is per client address; behind a proxy, every request otherwise comes from the proxy. nanobom reads the **first** address of the header, so the proxy must **replace** the header, not append to what the client sent. |
| **`/metrics` kept internal** | It needs no authentication; it reveals only instance-wide counts, but there is no reason to publish them. |

HSTS is left to the proxy: nanobom does not send it.

The examples below assume nanobom on `127.0.0.1:8080` and an internal network in `10.0.0.0/8`;
adapt both. Then [check the setup](#check-the-setup).

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name nanobom.example.org;

    ssl_certificate     /etc/letsencrypt/live/nanobom.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nanobom.example.org/privkey.pem;

    # 16 MiB SBOMs, base64-encoded by Dependency-Track clients.
    client_max_body_size 24m;

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
      # /metrics from the internal network only. The longer rule wins over the router above.
      traefik.http.routers.nanobom-metrics.rule: Host(`nanobom.example.org`) && Path(`/metrics`)
      traefik.http.routers.nanobom-metrics.entrypoints: websecure
      traefik.http.routers.nanobom-metrics.tls.certresolver: letsencrypt
      traefik.http.routers.nanobom-metrics.middlewares: nanobom-internal
      traefik.http.middlewares.nanobom-internal.ipallowlist.sourcerange: 10.0.0.0/8

volumes:
  nanobom-data:
```

No port is published: Traefik reaches the container on the Docker network. Traefik discards the
`X-Forwarded-*` headers of untrusted clients and sets its own, and has no body size limit by
default. Traefik 3 limits reading a request to 60 seconds by default
(`respondingTimeouts.readTimeout`); waiting uploads hold their request longer, so raise it on the
entry point as a precaution, in Traefik's static configuration:

```yaml
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: 330s
```

## Apache httpd

With the `proxy`, `proxy_http`, `headers` and `ssl` modules enabled (`a2enmod proxy proxy_http
headers ssl` on Debian and Ubuntu):

```apache
<VirtualHost *:443>
    ServerName nanobom.example.org

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/nanobom.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/nanobom.example.org/privkey.pem

    ProxyPreserveHost On
    # Uploads that wait for their evaluation (NANOBOM_UPLOAD_WAIT_SECONDS is 300 by default).
    ProxyTimeout 330
    RequestHeader set X-Forwarded-Proto "https"
    # mod_proxy appends the client's address to X-Forwarded-For: drop what the client sent first.
    RequestHeader unset X-Forwarded-For early

    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    <Location "/metrics">
        Require ip 10.0.0.0/8
    </Location>
</VirtualHost>

<VirtualHost *:80>
    ServerName nanobom.example.org
    Redirect permanent / https://nanobom.example.org/
</VirtualHost>
```

Apache accepts bodies of up to 1 GiB by default (`LimitRequestBody`).

## HAProxy

`crt` is a PEM file holding the certificate chain and its key:

```haproxy
defaults
    mode http
    timeout connect 5s
    timeout http-request 10s
    # Uploads that wait for their evaluation (NANOBOM_UPLOAD_WAIT_SECONDS is 300 by default).
    timeout client 330s
    timeout server 330s

frontend web
    bind :443 ssl crt /etc/haproxy/certs/nanobom.example.org.pem alpn h2,http/1.1
    bind :80
    http-request redirect scheme https code 301 unless { ssl_fc }
    http-request deny deny_status 403 if { path /metrics } !{ src 10.0.0.0/8 }
    # Not `option forwardfor`: it adds a header after the client's, and nanobom reads the first.
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
    default_backend nanobom

backend nanobom
    server nanobom 127.0.0.1:8080 check
```

HAProxy sets no body size limit.

## Behind a CDN or a second proxy

When requests cross another proxy first, such as Cloudflare, a cloud load balancer or a
tunnel, the address your proxy sees is that proxy's, and the client's comes in a header the first
proxy adds. Those headers are not safe to pass on as they are: Cloudflare, for one, appends to an
`X-Forwarded-For` the client sent, so its first address is whatever the client chose.

Have the last proxy, the one in front of nanobom, take the client's address from the first proxy
only when the request comes from it, and send nanobom a single address. With nginx and
Cloudflare, add the [real IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
directives to the `server` block above:

```nginx
    # One line per range listed at https://www.cloudflare.com/ips/
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 2400:cb00::/32;
    real_ip_header CF-Connecting-IP;
```

`$remote_addr`, and so `X-Forwarded-For` and the `allow` rules, are then the client's address.
For a load balancer that appends to `X-Forwarded-For`, use `real_ip_header X-Forwarded-For;` and
`real_ip_recursive on;` with `set_real_ip_from` set to its addresses.

Do not point a tunnel or a load balancer straight at nanobom with
`NANOBOM_TRUST_FORWARDED_HEADERS=true` unless it replaces `X-Forwarded-For`: otherwise leave the
option off, and sign-in rate limiting sees every client as the tunnel.

## Keep nanobom private, publish badges and public pages

[Badges](../reference/badges.md) and [public pages](../reference/public-pages.md) carry their
own key and need no session. To show them on the internet while the rest of nanobom stays on
your network, keep one host name, the one in `NANOBOM_PUBLIC_URL` (the links nanobom gives for
badges and pages use it), and open only their paths to everyone. With nginx, replace the
`location` blocks of the example above:

```nginx
    location / {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://127.0.0.1:8080;
    }

    location /api/organizations/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://127.0.0.1:8080;
        proxy_read_timeout 330s;
    }

    # Open to everyone: the key in the address is the authorization.
    location /badges/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location /public/ {
        proxy_pass http://127.0.0.1:8080;
    }
```

With Caddy:

```caddy
nanobom.example.org {
    @internal_only {
        not path /badges/* /public/*
        not remote_ip 10.0.0.0/8
    }
    respond @internal_only 403
    reverse_proxy 127.0.0.1:8080
}
```

`/metrics` is then internal too. Pages and badges are self-contained: they load nothing else
from nanobom. CI runners outside your network, such as GitHub-hosted ones, also need `/api/`;
open it the same way, since uploads require a token.

## Check the setup

From a machine outside the internal network, with your host name:

```sh
# The proxy reaches nanobom: prints {"status":"ok"}.
curl -fsS https://nanobom.example.org/healthz

# /metrics is refused: prints 403.
curl -s -o /dev/null -w '%{http_code}\n' https://nanobom.example.org/metrics

# A 20 MB body reaches nanobom: prints 401 (no token), not the proxy's 413.
head -c 20000000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null -w '%{http_code}\n' \
  -X PUT -H 'Content-Type: application/json' --data-binary @- \
  https://nanobom.example.org/api/v1/bom

# The client cannot choose its address: after 5 failed sign-ins, prints 429.
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w '%{http_code} ' -H "X-Forwarded-For: 192.0.2.$i" \
    -H 'Origin: https://nanobom.example.org' -d 'login=check&password=check' \
    https://nanobom.example.org/auth/login
done; echo
```

The last command prints `303 303 303 303 303 429`. Six `303` mean the proxy passes on the
address the client sent: each attempt counts against a different address, so rate limiting
does not hold. It also blocks sign-in from your address for a few seconds.

## Without a proxy

For a test instance on a private network, nanobom can be reached directly on port 8080. Keep
`NANOBOM_PUBLIC_URL` at the address you type in the browser (`http://192.168.1.20:8080`):
otherwise every form submission is refused as cross-site.
