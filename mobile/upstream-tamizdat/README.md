# Mobile integration module

This directory contains the Go module embedded into the iOS client build. The
code is consumed through `gomobile` and is not intended to be configured directly
from this folder by end users.

## Scope

- profile parsing
- client runtime lifecycle
- HTTP/2 session transport
- packet adapter integration
- diagnostics used by the iOS app and Network Extension

## iOS usage

The iOS app builds this module into `SamizdatClient.xcframework` during CI.
The Swift targets interact with it through the generated gomobile bindings.

Do not commit private endpoints, session parameters, signing material, or logs
containing user-specific runtime data.
