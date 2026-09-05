# Repository-local contract fixtures

This directory contains JSON, NDJSON, and JSON Schema fixtures owned by
`paperboat-tunnel` and consumed by its tests. Keep fixtures beside the tests
that use them and preserve the protocol and security behavior coverage.

Run affected checks from the repository root, including:

```sh
go test ./internal/connectorprotocol ./internal/contracttest
```
