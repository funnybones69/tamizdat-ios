# HANDOFF — продолжение VKS-работы (2026-09-25)

Прочитай это + `docs/VKS_TRANSPORT_STATE.md` (раздел «2026-09-24») — и продолжай.

## Что сделано (закрыто)

1. **iOS: поля Wake DNS / Wake zone в настройках VKS** — коммит `4bf5c6d` (push). Раньше их не было в UI → бикон не отправлялся → клиент дайлил мёртвую статичную telemost-комнату → 404 ConferenceNotFound. Это была причина «не подключается в whitelist через VKS» (лог телефона: `samizdat-2026-09-24T18-37-23Z.log`).
2. **Нативный путь: носитель по провайдеру** (`nativeconn.go`, оба дерева) — `transport.New(cfg.transportName())` вместо жёсткого `datachannel`. Коммиты `33283df` (tamizdat) / `cd2e763` (ios).
3. **mts-движок: страж DC-close** — закрытие неиспользуемого датаканала не рвёт сессию при `OnData==nil`. Коммит `2cfec2a`.
4. **IPA build 416** с фиксами: `ipa/milestones/Tamizdat-0.2.416-cd2e763-build-416.ipa`.
5. **MTS-комнату можно создавать программно** по owner-кукам: `createAndStartMTS` в `roomfactory.go` (POST event → session → start; delete через `deleteMTSEvent`). Протестировано живьём, работает.

## Открытые хвосты

1. **Нативный mts E2E не пройден.** На свежей комнате медиаплоскость пересекается (сервер получает треки клиента), но клиент churn-ит сессию ~1 c после dial (пул перенабирает) — handshake не успевает. Корень: источник churn не локализован (`resolveWakeSpec` молчит при ошибке бикона — nativeconn.go:517-519, надо добавить лог).
2. **Telemost-комнаты создаёт только владелец** (UI Yandex, куки протухли — 401). Динамического создания нет (roomfactory → ErrNoDynamicRoom → armed pool).
3. **Прод на ru2 ест 1.4 ГБ RSS** — утечка или норма под 6 живых сессий, не разобрано. Тест-инстанс `jz5` (~280 МБ) можно убить.
4. **Whitelist-режим на телефоне проверять так:** в настройках VKS заполнить `Wake DNS server` = `77.88.8.8:53`, `Wake zone` = `w.ai-archive.ru` → сервер по бикону выдаст комнату. Для telemost — только из armed-пула (см. хвост 2).

## Инфраструктура

- Ключ VKS (прод): `258adb9d…c930` (`/tmp/vkskey.txt` на ru2). Прод-юнит: `-vks-listen mts:…25356498874,telemost:…13704628620010 -vks-watch … -vks-beacon :53 -vks-beacon-zone w.ai-archive.ru`.
- Owner-куки MTS живые: `/opt/mts-autopromote/mts-owner.json` на ru2.
- Мой тест-хлам на ru2 убит, порты 18445/6072/11085 свободны. `srvmon` (tail журнала прода) работает.
- `mts-autopromote.service` продвигает гостей в LECTURER в прод-комнате MTS.

## Как появилась «инъекция Quill» в этой сессии

20.09 вызов `read C:\Users\Anarki\.pi\agent\SYSTEM.md` (там был тестовый Quill-промт) занёс блок в контекст OMP-сессии; компакция законсервировала его в архиве. Файл сейчас чист. **Новая сессия = чистый контекст, мусор не поедет.**
