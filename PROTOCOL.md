# Tamizdat iOS development notes

This file summarizes the public iOS client build/debug history. It is written
for maintainers who need to understand the repository layout and CI pipeline
without relying on private deployment details.

## Goal

Build and maintain an iOS Network Extension client using GitHub Actions,
Apple Developer signing, and a gomobile framework.

The app creates the required `NETunnelProviderManager` configuration, starts a
`PacketTunnelProvider`, exchanges diagnostic messages with the extension, and
binds the Go client runtime into the extension process.

## Repository

Main local path used by maintainers:

```text
C:\Users\user\projects\samizdat-ios
```

Public repository:

```text
https://github.com/funnybones69/tamizdat-ios
```

## Important build artifacts

The CI workflow exports signed IPA artifacts from `.github/workflows/build.yml`.
Artifacts are versioned by build number and commit short SHA.

## Problems found and fixes applied

### 1. `gomobile bind` failed: missing `golang.org/x/mobile/bind`

Symptom:

```text
unable to import bind: no Go package in golang.org/x/mobile/bind
unable to import bind/objc: no Go package in golang.org/x/mobile/bind/objc
```

Fix:

- Added `mobile/tools.go` with tool-only imports.
- Added/pinned `golang.org/x/mobile` in `mobile/go.mod`.
- Updated the CI workflow so Actions installs `gomobile`/`gobind` from the
  pinned `x/mobile` version instead of a floating `@latest`.

### 2. Swift gomobile API mismatch

Symptom:

Swift expected optional strings from gomobile functions, but generated API
returned non-optional `String` values.

Fix:

- Updated `samizdat-ios/SamizdatBridge.swift` to stop using `??` and optional
  chaining for gomobile string functions.

### 3. IPA export succeeded but inspect step failed

Symptom:

The archive/export step succeeded, but CI failed while inspecting embedded
provisioning profiles through `/dev/stdin`.

Fix:

- Reworked the workflow inspect step to decode profiles into temporary plist
  files before reading them with `PlistBuddy`.

### 4. App did not request a system network profile

Cause:

Having a Network Extension target inside the IPA is not enough. iOS shows the
system permission prompt only after `NETunnelProviderManager.saveToPreferences()`.

Fix:

- Added the profile-store helper.
- App now creates/saves a `NETunnelProviderManager`.
- App starts the provider session from the Connect action.

### 5. Initial extension was only a lifecycle stub

Cause:

The first `PacketTunnelProvider` only returned an error and did not process
packets.

Fix:

- Replaced the stub with a real `PacketTunnelProvider`.
- Added `NEPacketTunnelNetworkSettings`.
- Added IPv4/IPv6 route settings.
- Wired `packetFlow.readPackets` / `packetFlow.writePackets`.

### 6. Go runtime was not in the iOS framework

Fix:

- Added the Go client runtime to the mobile module.
- Added gomobile entry points for start/stop/status/logs.
- Added packet adaptation code for the extension process.

### 7. Logs were empty

Cause:

The main app read logs from its own process memory, while the runtime runs in the
extension process.

Fix:

- Added `NETunnelProviderSession.sendProviderMessage` from app to extension.
- Extension returns its log buffer to the app.
- Logs screen shows extension logs.

### 8. Extension hung after `PacketTunnelProvider startTunnel`

Observed log:

```text
info: PacketTunnelProvider startTunnel
```

Cause:

Extension did synchronous DNS work during `startTunnel`, which could block before
the completion handler.

Fix:

- Moved server DNS resolution to the main app before starting the extension.
- Added timeout around DNS resolution.
- Extension no longer performs synchronous DNS before applying network settings.

### 9. `Invalid NETunnelNetworkSettings tunnelRemoteAddress`

Cause:

`NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` received a value that was
not accepted by iOS.

Fix:

- Use a pre-resolved IPv4 address as `tunnelRemoteAddress`.
- Fallback to `127.0.0.1` only to keep settings syntactically valid.

### 10. Reserved-address DNS result broke bootstrap

Cause:

A reserved address from `198.18.0.0/15` was returned during bootstrap and then
used as a remote address.

Fix:

- Reject `198.18.*` and `198.19.*` bootstrap DNS results.
- Added an explicit DNS fallback path.
- Parser supports `connect_host` and `connect_port` query fields so the profile
  host can remain stable while the actual dial endpoint is explicit.

## Current state

The app starts the iOS Network Extension, applies network settings, and exposes
runtime diagnostics in the main UI.

Typical startup log sequence:

```text
info: preparing network profile
info: resolved server IPv4 before profile start
info: starting provider session
info: PacketTunnelProvider startTunnel
info: using pre-resolved server IPv4
info: applying packet network settings
info: provider session active ...
info: provider session started
```

This means:

- iOS system profile starts.
- `PacketTunnelProvider` starts.
- Network settings are accepted.
- Diagnostic messages reach the main app.
- Runtime status can be inspected from the SwiftUI logs screen.

## Files most relevant for debugging

App/profile/logs:

- `samizdat-ios/SamizdatBridge.swift`
- profile store
- `samizdat-ios/ContentView.swift`

Extension:

- `samizdat-tunnel/PacketTunnelProvider.swift`

Go bridge:

- `mobile/samizdat/samizdat.go`
- `mobile/socksstub/`

CI/signing:

- `.github/workflows/build.yml`
- `project.yml`
- `ExportOptions.plist`

## Maintainer checklist

Before testing a new IPA:

1. Remove stale iOS system profiles if behavior looks inconsistent.
2. Install the newest IPA.
3. Open the app.
4. Confirm the profile is saved.
5. Tap Connect.
6. Export logs from the first `preparing network profile` line through the first
   error.

Keep public logs and issues free of secrets, private endpoints, credentials,
profile blobs, signing material, or session parameters.
