# Embedded protocol module notes

This file intentionally keeps the public repository documentation at a high
level. The implementation is open source in this directory; maintainers should
use code review, tests, and issue-specific notes for detailed design discussion.

## Public design summary

The embedded Go module provides the network-session runtime used by the iOS
Network Extension. It exposes a compact client API, lifecycle hooks, status
metrics, and packet adaptation helpers for the Swift/gomobile boundary.

Core areas:

- profile parsing and validation
- authenticated HTTP/2 session setup
- connection pooling and lifecycle management
- runtime status counters
- diagnostic logging
- packet adapter support for the iOS extension

## Maintainer guidance

- Keep public issues and docs free of private endpoints and session material.
- Prefer neutral issue titles such as “network profile”, “provider session”,
  “relay session”, and “verification challenge”.
- Put reproducible build/test failures in GitHub issues with redacted logs.
- Keep operator-specific deployment details outside the public tree.

## Tests

Run module tests from the module directory:

```sh
go test ./...
```

For iOS-facing changes, also run the parent mobile module checks and the GitHub
Actions IPA workflow.
