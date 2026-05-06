# Changelog

All notable changes to this project will be documented in this file.

## v1.0.0 (2026-05-06)

### Added
- Full pytest test suite: 14 unit tests covering token generation, the `click` CLI, catalog-access JSON validation, error paths, and signature verification.
- 7 end-to-end integration tests that spin up a real `gizmodata/gizmosql:latest` container with TLS + JWT auth enabled (via `docker-py`) and verify that tokens produced by this utility authenticate via `adbc-driver-gizmosql`. Negative cases cover garbage tokens, expired tokens, wrong issuer/audience, and tokens signed with an untrusted key.
- New `[integration]` extra (`docker`, `adbc-driver-gizmosql`, `pyarrow`) and a registered `integration` pytest marker so unit and integration runs are cleanly separable.
- CI now runs unit tests on Python 3.10–3.13 and integration tests on a single Linux job; `build-n-publish` depends on both, so a broken test blocks releases.
- `CHANGELOG.md` is now wired into GitHub Release notes — the curated section for the tag is shown above the auto-generated PR/commit list.

### Changed
- README ADBC example now uses [`adbc-driver-gizmosql`](https://pypi.org/project/adbc-driver-gizmosql/) instead of `adbc_driver_flightsql`, matching the [official docs](https://docs.gizmosql.com/#/token_authentication?id=adbc-python).

### Fixed
- `datetime.UTC` was used unconditionally despite `requires-python = ">=3.10"` (the symbol was added in 3.11). Switched to `datetime.timezone.utc`, which works on all supported versions. Caught by the new 3.10 unit-test job.
