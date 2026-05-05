# sing-box-subscribe-cli

`sing-box-subscribe-cli` - маленький локальный CLI-конвертер подписок в готовый конфигурационный файл для `sing-box`.

Утилита принимает одну или несколько ссылок подписки, одиночные URI-ссылки или локальные файлы со ссылками, загружает JSON-template и формирует итоговый `config.json`.

Поддерживаются два режима совместимости:

- `sing-box` - обычный sing-box.
- `extended` - sing-box-extended с дополнительными транспортами, например `xhttp` и `mkcp`.

## Возможности

- Один бинарный файл без Python, pip, Flask и веб-сервера.
- Работа с локальными файлами и URL.
- Поддержка нескольких подписок через повторяющийся `--sub`.
- Подстановка узлов в template через `{all}`.
- Фильтры групп из template.
- Отдельный режим для `sing-box-extended`.
- Генерация готового JSON-конфига.
- Проверка результата через `sing-box check` или `sing-box-extended check`.

## Поддержка протоколов и форматов

| Протокол / формат | URI | JSON outbounds | Обычный sing-box | sing-box-extended |
|---|---:|---:|---:|---:|
| VLESS | Да | Да | Да | Да |
| VMess | Да | Да | Да | Да |
| Trojan | Да | Да | Да | Да |
| Shadowsocks | Да | Да | Да | Да |
| Hysteria | Да | Да | Да | Да |
| Hysteria2 / hy2 | Да | Да | Да | Да |
| TUIC | Да | Да | Да | Да |
| SOCKS / SOCKS5 | Да | Да | Да | Да |
| HTTP proxy | Да | Да | Да | Да |
| WireGuard | Нет для URI | Да | Да | Да |
| AnyTLS | Нет для URI | Да | Да | Да |

## Поддержка VLESS transport

| Transport | Обычный sing-box | sing-box-extended |
|---|---:|---:|
| `tcp` / без `type` | Да | Да |
| `ws` / `websocket` | Да | Да |
| `grpc` | Да | Да |
| `http` / `h2` | Да | Да |
| `httpupgrade` | Да | Да |
| `quic` | Да | Да |
| `xhttp` | Нет | Да |
| `mkcp` / `kcp` | Нет | Да |

## Установка

Скачайте бинарник из GitHub Releases:

```bash
curl -L -o sbs https://github.com/Mendex777/sing-box-subscribe-cli/releases/download/v0.1.0/sbs-linux-amd64
chmod +x sbs
./sbs --help
```

## Использование

### Обычный sing-box

```bash
./sbs \
  --target sing-box \
  --template ./template.json \
  --sub ./links.txt \
  --out ./config.json \
  --keep-going
```

Проверка:

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

Проверка:

```bash
sing-box-extended check -c ./config-extended.json
```

### Несколько подписок

```bash
./sbs \
  --target sing-box \
  --template ./template.json \
  --sub ./links-1.txt \
  --sub ./links-2.txt \
  --sub "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=ws&security=tls&path=%2Fws&sni=example.com#Example" \
  --out ./config.json
```

### Template по URL

```bash
./sbs \
  --target extended \
  --template "https://example.com/template.json" \
  --sub ./links.txt \
  --out ./config.json
```

### Подписки из файла

Файл `links.txt`:

```text
vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=ws&security=tls&path=%2Fws&sni=example.com#Example-WS
vless://22222222-2222-2222-2222-222222222222@example.org:443?encryption=none&type=grpc&security=tls&serviceName=grpc&sni=example.org#Example-gRPC
```

Команда:

```bash
./sbs --template ./template.json --sub ./links.txt --out ./config.json
```

## Template

В template можно использовать `{all}`:

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

Все найденные узлы будут добавлены в selector вместо `{all}`.

Также поддерживаются фильтры из template:

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

После генерации служебное поле `filter` удаляется из итогового конфига.

## Сборка из исходников

Требуется Go 1.22 или новее.

```bash
git clone https://github.com/Mendex777/sing-box-subscribe-cli.git
cd sing-box-subscribe-cli
go build -o sbs ./cmd/sbs
```

Linux amd64:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sbs-linux-amd64 ./cmd/sbs
```

Через Makefile:

```bash
make build
make release
```

## Релиз

Создать tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions соберет бинарники и прикрепит их к GitHub Release.

## Важное замечание

Конфиги с `transport.type = xhttp` не работают в обычном `sing-box`.

Для них нужен `sing-box-extended` и режим:

```bash
--target extended
```
