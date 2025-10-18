# SPF Client Tests

This directory contains integration tests for the SPF client library.

## Running Tests

Integration tests require a running SPF service and are gated behind the `integration-tests` feature flag.

**Prerequisites:**
- A running SPF service (default: `http://localhost:8080`)
- Optional: Set environment variables for custom configuration

**To run integration tests:**

```bash
cargo test --features integration-tests
```

**Important:** Integration tests will only compile and run when you use `--features integration-tests`. This prevents tests from failing in CI/CD environments where the SPF service may not be available.

## Environment Variables

Integration tests can be configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SPF_ENDPOINT` | SPF service endpoint URL | `http://localhost:8080` |

### Example with custom endpoint:

```bash
SPF_ENDPOINT=http://127.0.0.1:8080 \
cargo test --features integration-tests
```
