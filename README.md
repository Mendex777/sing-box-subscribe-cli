# sing-box-subscribe-cli

`sing-box-subscribe-cli` is a small local CLI converter that builds a ready-to-use `sing-box` configuration from subscription links.

It accepts one or more subscription URLs, raw URI links, local files with links, and a JSON template, then writes the final `config.json`.

Compatibility targets:

- `sing-box` - regular sing-box.
- `extended` - sing-box-extended with extra transports such as `xhttp` and `mkcp`.

Russian documentation: [README.ru.md](README.ru.md)

## Features

- Single binary, no Python, pip, Flask, or web server.
- Local files and remote URLs.
- Multiple subscriptions via repeated `--sub`.
- Template placeholders with `{all}`.
- Template group filters.
- Separate compatibility mode for `sing-box-extended`.
- JSON config generation.
- Output validation with `sing-box check` or `sing-box-extended check`.

## Protocol and Format Support

| Protocol / format | URI | JSON outbounds | sing-box | sing-box-extended |
|---|---:|---:|---:|---:|
| VLESS | Yes | Yes | Yes | Yes |
| VMess | Yes | Yes | Yes | Yes |
| Trojan | Yes | Yes | Yes | Yes |
| Shadowsocks | Yes | Yes | Yes | Yes |
| Hysteria | Yes | Yes | Yes | Yes |
| Hysteria2 / hy2 | Yes | Yes | Yes | Yes |
| TUIC | Yes | Yes | Yes | Yes |
| SOCKS / SOCKS5 | Yes | Yes | Yes | Yes |
| HTTP proxy | Yes | Yes | Yes | Yes |
| WireGuard | Not as URI | Yes | Yes | Yes |
| AnyTLS | Not as URI | Yes | Yes | Yes |

## VLESS Transport Support

| Transport | sing-box | sing-box-extended |
|---|---:|---:|
| `tcp` / no `type` | Yes | Yes |
| `ws` / `websocket` | Yes | Yes |
| `grpc` | Yes | Yes |
| `http` / `h2` | Yes | Yes |
| `httpupgrade` | Yes | Yes |
| `quic` | Yes | Yes |
| `xhttp` | No | Yes |
| `mkcp` / `kcp` | No | Yes |

## Install

Download a binary from GitHub Releases:

```bash
curl -L -o sbs https://github.com/Mendex777/sing-box-subscribe-cli/releases/download/v0.1.0/sbs-linux-amd64
chmod +x sbs
./sbs --help
```

## Usage

### Regular sing-box

```bash
./sbs \
  --target sing-box \
  --template ./template.json \
  --sub ./links.txt \
  --out ./config.json \
  --keep-going
```

Validate:

```bash
sing-box check -c ./config.json
```

### sing-box-extended

```bash
./sbs \
  --target extended \
  --template ./template.json \
  --sub ./links.txt \
  --out ./config-extended.json \
  --keep-going
```

Validate:

```bash
sing-box-extended check -c ./config-extended.json
```

### Multiple subscriptions

```bash
./sbs \
  --target sing-box \
  --template ./template.json \
  --sub ./links-1.txt \
  --sub ./links-2.txt \
  --sub "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=ws&security=tls&path=%2Fws&sni=example.com#Example" \
  --out ./config.json
```

### Remote template

```bash
./sbs \
  --target extended \
  --template "https://example.com/template.json" \
  --sub ./links.txt \
  --out ./config.json
```

### Subscription file

`links.txt`:

```text
vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=ws&security=tls&path=%2Fws&sni=example.com#Example-WS
vless://22222222-2222-2222-2222-222222222222@example.org:443?encryption=none&type=grpc&security=tls&serviceName=grpc&sni=example.org#Example-gRPC
```

Command:

```bash
./sbs --template ./template.json --sub ./links.txt --out ./config.json
```

## Template

Use `{all}` in an outbound group:

```json
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "Proxy",
      "outbounds": ["{all}", "direct"]
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

All parsed nodes will be inserted into the selector in place of `{all}`.

Template filters are supported:

```json
{
  "type": "selector",
  "tag": "Sweden",
  "outbounds": ["{all}"],
  "filter": [
    {
      "action": "include",
      "keywords": ["Sweden|SE|Швеция"]
    }
  ]
}
```

The helper `filter` field is removed from the generated config.

## Build From Source

Go 1.22 or newer is required.

```bash
git clone https://github.com/Mendex777/sing-box-subscribe-cli.git
cd sing-box-subscribe-cli
go build -o sbs ./cmd/sbs
```

Linux amd64:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sbs-linux-amd64 ./cmd/sbs
```

With Makefile:

```bash
make build
make release
```

## Release

Create a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will build binaries and attach them to the GitHub Release.

## Important

Configs with `transport.type = xhttp` do not work with regular `sing-box`.

Use `sing-box-extended` and:

```bash
--target extended
```
