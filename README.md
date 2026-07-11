# tamizdat-ios

Experimental iOS client for the Tamizdat packet-network stack.

The project combines a SwiftUI control app, an iOS Network Extension, and a
Go runtime built with `gomobile`. The public repository is intended to document
build structure, signing requirements, and client-side integration points.

## Architecture

```text
┌──────────────────────────────────────────────┐
│ SwiftUI app                                  │
│  ├─ profile/configuration editor             │
│  ├─ status and diagnostics UI                │
│  ├─ local notification preferences           │
│  └─ Swift ↔ Go bridge                        │
│                                              │
│ Network Extension                            │
│  ├─ PacketTunnelProvider lifecycle           │
│  ├─ packet adapter                           │
│  └─ gomobile client runtime                  │
└──────────────────────────────────────────────┘
```

## Current status

The CI pipeline builds a signed IPA from the public tree:

```text
Go sources → gomobile framework → Xcode project → archive/export → IPA artifact
```

The app stores a Tamizdat profile, creates the required iOS Network Extension
configuration, starts/stops the extension, and exposes diagnostic status from the
extension process back to the SwiftUI app.

## Repository layout

```text
mobile/                          # Go module used by gomobile
  samizdat/                      # public gomobile entry points
  socksstub/                     # iOS runtime bridge
  upstream-tamizdat/             # embedded protocol module

samizdat-ios/                    # SwiftUI app target
  App.swift
  ContentView.swift
  SettingsView.swift
  LogView.swift
  SamizdatBridge.swift
  Info.plist
  samizdat-ios.entitlements
  Assets.xcassets/

samizdat-tunnel/                 # Network Extension target
  PacketTunnelProvider.swift
  Info.plist
  tamizdat-tunnel.entitlements

project.yml                      # XcodeGen config
ExportOptions.plist              # Ad-hoc export options
.github/workflows/build.yml      # CI build and IPA upload
```

## Building locally on macOS

```sh
brew install xcodegen go
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
( cd mobile && gomobile bind -target=ios -o ../Frameworks/SamizdatClient.xcframework ./samizdat ./socksstub )
xcodegen generate
open tamizdat-ios.xcodeproj
```

## CI build

The normal build path is GitHub Actions:

```text
git push → GitHub Actions → signed IPA artifact
```

Required signing material is supplied via repository secrets. Do not commit
certificates, provisioning profiles, passwords, API keys, session parameters, or
runtime logs containing private values.

## Bundle / signing

| Item | Value |
|---|---|
| Team ID | `DRMTP6V372` |
| App bundle ID | `com.anarki.samizdat-test` |
| Extension bundle ID | `com.anarki.samizdat-test.tunnel` |
| App Group | `group.com.anarki.samizdat-test` |
| App profile | `Samizdat Test AdHoc` |
| Extension profile | `Samizdat Tunnel AdHoc` |
| Certificate | Apple Distribution |

## Required GitHub Secrets

| Name | Contents |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | base64 of the `.p12` |
| `P12_PASSWORD` | password protecting the `.p12` |
| `BUILD_PROVISION_PROFILE_BASE64` | base64 of the app provisioning profile |
| `BUILD_TUNNEL_PROVISION_PROFILE_BASE64` | base64 of the extension provisioning profile |
| `KEYCHAIN_PASSWORD` | temporary CI keychain password |
