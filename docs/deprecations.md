# Deprecations

## RFC 7591 Dynamic Client Registration

MCP 2026-07-28 [deprecates DCR](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) in favor of Client ID Metadata Documents. DCR remains available for a minimum twelve-month spec window.

This bundle:

- Enables `POST {authorization_prefix}/register` when `mcp_oauth.dcr.enabled` is true (default)
- Advertises `registration_endpoint` in RFC 8414 metadata while DCR is on
- Calls `trigger_deprecation('omouren/mcp-oauth-bundle', '0.1', …)` on every successful registration attempt

Greenfield apps can set `dcr.enabled: false`.

Removing DCR will be a major version of this bundle, aligned with dropping `registration_endpoint`.
