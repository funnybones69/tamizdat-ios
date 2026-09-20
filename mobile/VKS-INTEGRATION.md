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

## Управление под белыми списками: ru2 недоступен напрямую (design note)

Под мобильными белыми списками РФ (default-deny) устройство видит только
разрешённые отечественные сервисы. Прямой адрес нашего сервера (ru2 и его
выходы) в этот список не входит — значит:

- **Прямой зависимости клиента от ru2 быть не должно.** Аудит (2026-09-20):
  в iOS-коде и вендоренном Go-дереве нет ни IP, ни хостов ru2/gateway/server;
  в `internal/cmd/pkg` tamizdat — только комментарии и фикстуры, в корневых
  скриптах — ops-комментарий `scripts/vks/run_vks_provider.sh`. Рантайм-
  зависимостей нет.
- **Весь путь клиент → сервер идёт через комнаты провайдеров** (VKS-лестница
  telemost/wbstream/jazz/mts): комнаты на белых списках, поверх — olcRTC-
  туннель, внутри — H2 к tamizdat-серверу. Управление (доставка конфига,
  room-assignment, обновления) едет тем же путём.
- **Приоритет путей** в `dialUpstream`: VK TURN → VKS-чейн → samizdat →
  direct. Прямой путь — последний резерв (работает вне белых списков);
  UI/settings не должен обещать доступность ru2 без транспорта.
- **Для оператора**: проверки серверов выполняются с самих серверов или
  SSH-хаба, не с клиентских устройств под белыми списками.

## Ограничения текущей iOS-сборки (2026-09-20, по ревью)

- **Channel-id на iOS нет**: токен привязки пары выводится только из RoomURL —
  одна комната = одна клиент-серверная пара; выделяй комнату на устройство
  (десктопный `-vks-channel-id` не совместим с iOS-клиентом в общей комнате).
- **VK TURN приоритетнее**: при активном TURN-полисе лестница не стартует
  (экономия памяти extension'а); цепочка dialUpstream проверяет TURN первым.
- **Логи лестницы** (olc-клиент + ladder) бриджатся в extension-log через
  `routeStdLogsToSink`; чейн-фейлы больше не гасятся verbose-гейтом.
- **Память**: лестница = полный pion+vp8channel стек в extension'е (~25-30 МБ
  бюджет против ~50 МБ jetsam). При jetsam: снижать FPS/BatchSize, сокращать
  провайдеров.
- **Rewire**: смена сети (Wi-Fi↔сотовая) лестницу не перезапускает — полагается
  на внутренний reconnect; проверить отдельным тестом.
- **5-секундный дедлайн чейн-диала**: флапающая комната больше не съедает
  15 с из бюджета потока (быстрый фолбэк на samizdat).
