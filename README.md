# Email Validator 📨

A robust Python tool to validate email addresses using format checks and MX record lookups, with support for DNS retries, caching, detailed diagnostics, and full unit tests.

## Features

- RFC-compliant email format validation (via `email-validator`)
- MX record DNS lookup with:
  - Timeout and retries
  - Caching (thread-safe, with TTL)
  - Priority sorting
- Rich CLI output with interactive mode
- Full test suite with mocks and integration tests

## Installation

```bash
pip install -r requirements.txt
