# Validation harness for scan findings 1-7

The checks in this folder show that each of the seven scan findings is real, and that a fix
actually resolves it. Every check asserts the fixed behaviour:

- Before the fix, the check fails. It reproduces the issue and the failure message names the problem.
- After the fix, the check passes, so the fix is verified.

The harness does not touch production code. The JUnit checks live under
`src/test/java/io/github/adorsysgis/keycloakstatuslist/validation/` and are named `*Check`.
Surefire only picks up `*Test` and `*IT` classes, so normal `mvn test` builds and CI stay green.
The checks only run when the script asks for them via `-Dtest`.

## How to run

```bash
# Before the fix: proves every finding is real (exit 0 = all 7 reproduce)
./validation/run-checks.sh --expect broken

# After the fix: proves every fix works (exit 0 = all 7 fixed)
./validation/run-checks.sh --expect fixed

# Run one finding only (a smaller, ticket-sized run), e.g. finding 1
./validation/run-checks.sh --only 1

# Plain run: prints a PASS/FAIL table, exit 0 when everything passes
./validation/run-checks.sh
```

The script can be run from any directory; it changes into the module root itself. You only need a
JDK and the project Maven wrapper, no Docker, because all checks are unit-level. Maven output is
written to `target/validation/` (`java-checks.log`, `junit-dependency-tree.log`), and surefire
details to `target/surefire-reports/`.

Status meanings:

| Status  | Meaning                                             |
| ------- | --------------------------------------------------- |
| `FAIL`  | issue still present, expected before the fix        |
| `PASS`  | issue fixed, expected after the fix                 |
| `ERROR` | check could not run, fix the harness or build first |

## What each check asserts

| #   | Finding (symptom)                                                                                                                          | Check                                                              | Before fix (reproduces)                                                                         | After fix (verifies)                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| 1   | Malformed numeric realm attributes throw a raw `NumberFormatException`, breaking issuance/metadata even with `status-list-mandatory`       | `Finding01ConfigParsingCheck` (3 tests)                            | constructor throws on `status-list-issuance-timeout=10000ms`; getters throw on `10s`            | construction survives; getters fall back to defaults or throw a descriptive error |
| 2   | `StatusListProtocolMapper` creates a pooled `CloseableHttpClient` per request; `Provider.close()` never closes it                          | `Finding02HttpClientLifecycleCheck`                                | "Created 2 HTTP clients ... closed only 0"                                                      | each created client is closed on session close, or one client is shared/cached    |
| 3   | `pom.xml` hardcodes `junit-jupiter-params` 5.12.2 while the BOM manages 5.14.1 (skewed JUnit artifacts)                                    | `run-checks.sh` (via `mvn dependency:tree`)                        | resolved `5.12.2`, expected `5.14.1`                                                            | resolved version equals the `junit.version` property                              |
| 4   | `getStatusListMaxEntries()` logs WARN on every call when `status-list-max-entries` is unset (the documented default)                       | `Finding04ConfigLoggingCheck`                                      | captured WARN `No max entries value configured ...`                                             | no WARN on the default path; WARN kept for invalid values                         |
| 5   | `registerIssuer()` logs `response.getHeaders().toString()`, a JVM array identity like `[Lorg.apache.hc.core5.http.Header;@6b0bcea5`        | `Finding05ResponseHeaderLogCheck`                                  | debug log contains the array identity, not header contents                                      | debug log shows actual headers (e.g. `X-Trace-Id: abc-123`)                       |
| 6   | `docs/technical-reference.md` documents 11 of the 13 `IssuedCredentialStatus` fields; `activeCount` description omits unmapped credentials | `run-checks.sh` (grep)                                             | `mappingStatus` / `countsTowardQuota` absent; `activeCount` row lacks "no mapping" wording      | both fields documented; `activeCount` wording covers credentials with no mapping  |
| 7   | (a) `MockKeycloakTest.setPrivateField` silently no-ops on unknown field names; (b) no repository-level tests at all                        | (a) `Finding07aTestHelperCheck` + (b) `run-checks.sh` (file check) | (a) "Expected ... to be thrown, but nothing was thrown"; (b) `StatusListRepositoryTest` missing | (a) helper fails fast, still sets existing fields; (b) at least 3 `@Test` methods |

Check 7b expects `src/test/java/.../jpa/repository/StatusListRepositoryTest.java` to contain at
least three tests covering next-index reservation, list-id rollover, and latest-mapping locking.
If the fix names the class differently, update `check_finding_7b` in `run-checks.sh` to match.

## Why findings are grouped into 4 tickets

The seven findings are grouped by change area so each ticket stays small and easy to review. A
ticket is done when its checks pass under `./validation/run-checks.sh --only <n>`, the existing
suite stays green (`./mvnw test`), and `./mvnw spotless:check` passes.

| Ticket | Findings | Change surface                                                                                         | Rationale                                                                |
| ------ | -------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| **1**  | 1, 4     | `StatusListConfig` only (numeric parsing fallback + log level)                                         | same root cause: attribute parsing/logging in one class                  |
| **2**  | 2, 5     | `StatusListProtocolMapper.close()`, `CustomHttpClient`, `ApacheHttpStatusListClient` (1 log statement) | both are HTTP-client-layer defects: resource lifecycle + log readability |
| **3**  | 7a, 7b   | test sources only: `MockKeycloakTest` fail-fast + new `StatusListRepositoryTest`                       | test-infrastructure work; zero production-code risk                      |
| **4**  | 3, 6     | `pom.xml` (one version) + `docs/technical-reference.md`                                                | build/docs alignment; trivial diffs, no runtime behaviour                |

Ticket 1 is the only one that touches issuance behaviour. If maintainers prefer, findings 1 and 4
can ship first, since ticket 2's checks and ticket 1's checks are independent of each other.

## Design notes

- The checks assert fixed behaviour (TDD style). A red run before the fix is evidence, not a
  broken build. Use `--expect broken` or `--expect fixed` to make the exit code unambiguous.
- No pom or CI changes are needed. `-Dtest=Finding*Check` overrides surefire's includes, and the
  `*Check` suffix keeps the classes out of every normal build.
- The checks are deliberately flexible about the fix strategy. Finding 2 accepts either closing
  the client on session close or sharing one client per realm. Finding 1 accepts falling back to a
  default or throwing a descriptive error that names the property. Only the raw
  `NumberFormatException` and the broken constructor count as failures.
- Logs and reports go under `target/` (already git-ignored). The harness only adds
  `validation/run-checks.sh`, `validation/README.md` and the five `*Check` classes.
