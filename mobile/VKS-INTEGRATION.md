# VKS room transports (iOS)

## Что это

`socksstub` получил новый upstream-режим **VKS**: клиент лестницы tamizdat
(комнатные транспорты ВКС-провайдеров: `telemost`, `wbstream`, `jazz`, `mts`)
крутится в процессе основного приложения и поднимает локальный SOCKS5-листенер;
каждый TCP-поток, принятый socksstub, чейнится через него.

## Что вендорено

| Путь | Что | Откуда |
|---|---|---|
| `upstream-tamizdat/vks/` | клиент/серверные обёртки VKS + olc-ядро | tamizdat `internal/vks` (импорты переписаны `github.com/detectqq/tamizdat` → `github.com/funnybones69/tamizdat`, вынесено из `internal/`, чтобы главный модуль мог импортировать) |
| `third_party/datachannel/` | форк `github.com/pion/datachannel` (нестандартный DCEP odin-SFU для MTS/Jazz) | tamizdat `third_party/datachannel`, подключён через replace главного модуля |
| `socksstub/vks.go` | gomobile-API + SOCKS5-чейн-диалер | новый файл |

`go.mod` главного модуля: `replace github.com/pion/datachannel => ./third_party/datachannel`.
Требуется Go ≥ 1.26.3 (модуль `codeberg.org/rape4me/kc` — VP8-кодек для vp8channel).

## Публичное gomobile-API

```
StartVKSUpstream(specs, keyHex, shortIDHex string, listenPort int) string
StopVKSUpstream() string
VKSUpstreamRunning() bool
VKSUpstreamStatsJSON() string
```

- `specs` — лестница через запятую: `"telemost:https://telemost.yandex.ru/j/123,wbstream:stab"`.
- `keyHex` — общий ключ olcRTC-wire (как `-vks-key` в CLI).
- `shortIDHex` — `master_shortid` пользователя tamizdat.
- `listenPort` — loopback-порт SOCKS5 для VKS-листенера.

`StartVKSUpstream` неблокирующий, возвращает JSON-статус; лестница живёт в
фоне и сама переключает профили при отказе.

## Путь данных

```
NE (hev-socks5-tunnel) → socksstub SOCKS5 → чейн (SOCKS5 CONNECT 127.0.0.1:<listenPort>)
  → VKS ladder client → WebRTC-комната (ВКС-провайдер РФ) → сервер tamizdat → выход за границей
```

Приоритет в `dialUpstream`: **VK TURN netstack → VKS-чейн → samizdat → direct**.
UDP: olc-клиент потоковый, поэтому VKS-путь — только TCP; UDP-потоки сохраняют
прежний приоритет (VK TURN / samizdat / direct).

## Сборка

CI не менялся: `gomobile bind` уже бандлит `./samizdat ./socksstub`, а
вендоренное дерево компилируется под apple-таргеты. Локальная проверка:

```
cd mobile
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./socksstub ./samizdat
CGO_ENABLED=0 GOOS=ios   GOARCH=arm64 go build ./socksstub ./samizdat
```

Реальный `gomobile bind → xcframework` выполняется на macOS-раннере CI
(`runs-on: macos-15`).

## Замечания

- Режимы upstream взаимоисключающие: VKS, VK TURN и samizdat не должны быть
  активны одновременно; порядок в `dialUpstream` задаёт приоритет.
- Ошибка чейна не обрывает поток: пишется в лог (`vks chain dial … failed`) и
  поток идёт по следующему по приоритету пути.