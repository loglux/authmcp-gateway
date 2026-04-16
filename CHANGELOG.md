# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.29] - 2026-04-16

### Fixed
- Applied configured backend `tool_prefix` values to tool names returned from the
  aggregated `/mcp` endpoint while preserving raw backend names on per-server
  endpoints.
- Mapped prefixed aggregate tool names back to raw backend tool names for
  `tools/call`, keeping prefixed listings and execution routing consistent.

## [1.2.28] - 2026-04-16

### Changed
- Marked the package as `Production/Stable` in PyPI metadata instead of `Beta`.
- Expanded PyPI classifiers to better reflect the runtime and deployment model:
  `Environment :: Web Environment`, `Framework :: AsyncIO`,
  `Topic :: Internet :: Proxy Servers`, `Topic :: Security :: Cryptography`,
  `Topic :: System :: Monitoring`, and
  `Topic :: System :: Systems Administration :: Authentication/Directory`.

## [1.2.27] - 2026-03-21

### Fixed
- Omitted `null` fields such as `client_secret` and `scope` from Dynamic Client
  Registration responses when those values are not issued, improving strict client
  compatibility.
- Added `id_token` to the authorization code token response when `openid` is
  requested.
- Returned `scope` in the authorization code token response for better OAuth/OIDC
  interoperability.
- Improved `/auth/me` compatibility for OIDC-style userinfo consumers.

### Changed
- Improved ChatGPT connector compatibility for OAuth, DCR, and authorization code
  flows.

[1.2.29]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.29
[1.2.28]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.28
[1.2.27]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.27
