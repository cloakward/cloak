# Cloak Privacy Disclosure

Cloak has no hosted service, telemetry, analytics, update checks, or account
system. The vault, daemon, audit log, and policy file live on the user's
machine.

The macOS Claude Desktop extension (`Cloak-*.dxt`) bundles only the local
`cloak-mcp` shim. It connects to the local `cloakd` daemon over a Unix domain
socket and does not send data to Cloak or cloakward.

Some MCP tools intentionally contact external services on the user's behalf:

- `proxy_authenticated_http_request` sends the user-provided request to the
  upstream HTTPS host allowed by Cloak policy. The daemon attaches the selected
  stored secret to that outbound request and returns the upstream status,
  headers, and body to the MCP client after best-effort redaction of exact
  secret echoes.
- `mint_short_lived_token` can call AWS STS to exchange a stored parent secret
  for temporary AWS credentials. The temporary credential is returned to the
  MCP client by design.

Those upstream services process the request data according to their own
privacy policies. Users should only allow hosts and token scopes they trust.
