# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-06

### Added

- Initial release of Keycloak Token Status Plugin
- Status list protocol mapper for OID4VC credentials
- Integration with external OAuth 2.0 Status List servers
- Support for token status publishing (VALID, REVOKED)
- Configurable realm-level properties:
  - `status-list-enabled`: Enable/disable the service
  - `status-list-server-url`: External status list server URL
  - `status-list-token-issuer-prefix`: Token issuer ID prefix
  - `status-list-mandatory`: Control whether publication failures block issuance
- Credential revocation REST API endpoint
- SD-JWT-VP validation service for credential revocation requests
- JPA persistence layer for status list mappings
- Comprehensive test coverage with JUnit and Mockito
- TLS 1.2/1.3 secure communication support
- Bearer token authentication for status list server
- Detailed logging with unique request IDs for traceability
- Docker Compose setup for local development (Keycloak 26.4.5 + PostgreSQL)
- GitHub Actions CI/CD pipeline with Spotless formatting checks

### Security

- Secure HTTP client with fixed connection timeouts (30s connect, 60s read)
- Proper handling of realm public keys and signing algorithms
- No retry mechanism by default to prevent thread blocking
- Minimal sensitive information logging

[0.1.0]: https://github.com/ADORSYS-GIS/token-status-link/releases/tag/v0.1.0
