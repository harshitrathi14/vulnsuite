# Approved response and operational integrations

The shipped configuration examples are disabled. Merge the control-plane fragment
into the protection service configuration and the agent fragment into each enrolled
host's local configuration. Imports and plan creation do not send outbound messages
or change firewalls. No live provider changes are part of repository validation.

## SIEM and ticketing bridge

- Configure a named HTTPS webhook endpoint owned by your organisation. Alert data
  cannot choose its destination. The webhook contract supports SIEM ingestion and
  ticket creation through an organisation-operated adapter; it is not a native
  Jira, ServiceNow, or Splunk API client.
- Supply bearer and signing secrets via the configured environment variable names,
  at least 24 characters each. URLs cannot contain credentials, query secrets, or
  fragments. TLS verification is mandatory; redirects and environment proxy/TLS
  overrides are disabled.
- Messages are JSON envelopes: `{"type":"security.alert","data":{...}}` or an
  incident event produced by the control plane. Treat alert strings as untrusted
  text at the destination. Ticket adapters should render text without executing it.
- Verify `X-VulnSuite-Signature` as `v1=` followed by hex HMAC-SHA256 of the exact
  bytes `X-VulnSuite-Timestamp + "." + request_body`, using the signing secret.
  Reject timestamps more than five minutes from receiver time and compare signatures
  in constant time. Authenticate the bearer token independently.
- Persist `Idempotency-Key` before acknowledging a request. The worker retries
  transport failures, HTTP 429, and HTTP 5xx with bounded exponential backoff.
  Delivery is at least once; an adapter must return its prior success for a
  duplicate key to prevent duplicate tickets. Other non-2xx responses fail visibly
  for operator correction, without forwarding response bodies into the audit trail.
- SQLite stores payloads, attempts, leases, next delivery time, and sanitized errors.
  A worker crash releases work after its 120-second lease. Keep clocks synchronised.

## Cloudflare WAF

- Configure one zone and its existing zone-level `http_request_firewall_custom`
  entry-point ruleset. A zone-scoped API token needs the relevant WAF write
  permission. Add your operational IPs to `protected_networks`; retain an explicit
  `permitted_networks` policy.
- An analyst requests a `cloud_waf_block` playbook against an alert. A different
  administrator approves the reviewed IP, reason, scope, and deadline. The worker
  applies one custom rule; it never replaces the whole ruleset.
- Every rule contains both the exact source IP and
  `http.request.timestamp.sec lt EXPIRES_AT`. Cloudflare evaluates this timestamp
  predicate for each request. Duration is 60–3,600 seconds, fixed when the plan is
  created. Approval delay and worker retries consume that duration.
- The stable per-job rule reference allows retries after an uncertain HTTP outcome
  to reconcile existing work. Expired jobs that may have applied are reconciled and
  cleaned. Cleanup removes only a matching owned rule; a rule changed externally
  is left for operator review.
- Failed cleanup is persisted as `rollback_failed` and retried. The original rule
  stops matching after its embedded deadline even while cleanup is unavailable.
  Disabling new WAF actions does not stop cleanup; keep the original scope and
  credentials configured until existing jobs finish.
- Cloudflare rule quotas, propagation delays, API rate limits, and rule ordering
  still apply. Earlier skip/allow policies can bypass later rules. The connector
  requires the timestamp expression to be accepted; it never falls back to a
  permanent IP-list entry. Direct-origin traffic does not traverse Cloudflare.
  Provider or administrator edits to a deployed rule invalidate its original
  expiry guarantee and are reported rather than overwritten.

Provider references used for this implementation:

- [Create a zone custom rule](https://developers.cloudflare.com/waf/custom-rules/create-api/).
- [Request timestamp field](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.sec/).
- [Delete a rule](https://developers.cloudflare.com/ruleset-engine/rulesets-api/delete-rule/).

## Microsoft Entra ID identity response

- Register an application in the tenant with application permissions only:
  `User.RevokeSessions.All` for `identity_revoke_sessions`, `User.ReadWrite.All`
  for `identity_disable_account`. Scope it to an administrative unit of the
  accounts the SOC may act on where the tenant supports it. Store the client
  secret (or a certificate-backed secret broker's output) in the environment
  variable named by `client_secret_env`; it never appears in configuration.
- `allowed_domains` lists the UPN suffixes the connector may touch;
  `protected_users` lists break-glass and service accounts that are never
  touched, whatever the alert says; `upn_domain` completes bare or `DOMAIN\user`
  evidence from Windows and SSH logs into a UPN.
- The acting account is taken from the event that raised the alert (login
  evidence), never from the request body. An analyst requests
  `identity_revoke_sessions` (one-shot: every refresh token and session is
  invalidated, forcing re-authentication under the identity provider's policy)
  or `identity_disable_account` (sign-in disabled for 60–3,600 seconds). A
  different administrator approves. The durable worker exchanges the client
  credential for a token, confirms the user object matches the approved UPN,
  then acts. A disable is re-enabled by the worker at expiry, and immediately
  when the originating host is revoked; an account already disabled by someone
  else is left alone and the job fails as `account_already_disabled`.
- Revoking sessions does not end an established VPN or RDP session that does
  not re-validate tokens, and disabling an account does not disconnect it; pair
  with `isolate_host` or network response where needed. Conditional-access
  and privileged-role changes are out of scope.

Provider references used for this implementation:

- [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).
- [revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions).
- [Update user (accountEnabled)](https://learn.microsoft.com/en-us/graph/api/user-update).

## Linux quarantine and isolation

- Control-plane approvals and local `response_policy.enabled` plus
  `allowed_actions` are independently required. The host fetches only its own
  commands through the existing authenticated agent connection. All fetched plans
  have a dispatch deadline; an expired plan cannot initiate local containment.
- `quarantine_file` requires malware alert path/hash evidence and an exact path in
  the host's local `allowed_paths`. There are no directory wildcards. Provision an
  existing vault owned by the agent executor with mode `0700`, on the same
  filesystem as the target. Parent components and target symlinks are rejected;
  hard-linked, non-regular, oversized, or hash-mismatched files are rejected.
- Quarantine atomically moves bytes into the private vault, removes executable and
  writable permissions, and persists a manifest before the move. It does not delete
  file contents. `restore_file` requires a separately approved previous job and
  rechecks the retained SHA-256. Restoration never overwrites an existing path.
  Setuid/setgid bits are not restored. Existing process mappings or open file
  descriptors are not terminated by moving a file; investigate those separately.
- `isolate_host` accepts a 60–3,600 second duration and fixed local management
  networks/ports. Control-plane policy must match the host policy. Include every
  control-plane and administrator address required during isolation; the example
  address is a placeholder. The configured path must work without DNS refresh
  during isolation, or additional management routing must be provided.
- The agent generates its own nftables script. A dedicated table covers IPv4/IPv6
  input, output, and forwarding, preserving loopback, configured TCP management
  traffic, and necessary IPv6 neighbour discovery. Both address families have timed
  sets; when their elements expire, the drop predicates stop matching without a
  running agent. A retry never refreshes an existing job's timer.
- `release_host` removes only the table belonging to the approved earlier job.
  Expired empty isolation tables are also cleaned by the agent on later polls.
  Existing firewall policies still apply; an accept in this table cannot override
  an unrelated drop policy. Linux nftables and the necessary privileges are required.
  Containers with their own network namespaces need their own enforcement scope.
- The agent writes action receipts before acknowledging them to the server. Network
  failures retry the receipt without repeating execution. Local manifests recover
  interrupted quarantine/restoration moves. Receipts and server audits record
  outcome, evidence, actor approval, and expiry without subprocess error output.

Reference: [nftables command and set-timeout semantics](https://netfilter.org/projects/nftables/manpage.html).

## Worker and staged validation

Start the worker only when outbound delivery and approved provider response are
intended. From the repository root containing the `vulnsuite` package:

```bash
python3 -m vulnsuite.protection.response_worker \
  --config /etc/vulnsuite/server.json \
  --database /var/lib/vulnsuite/protection.db --watch
```

Use `--once` for one queue-processing pass. This is an executor, not a dry run.
The API and worker must use the same control-plane database and connector config.
The worker never performs local host containment; enrolled agents execute those jobs.

Before a production rollout:

- Use a receiver fixture to verify HMAC, replay rejection, duplicate handling,
  receiver outages, worker restart, and the resulting ticket/SIEM event.
- Use a staging Cloudflare zone to verify allowed rules, rule ordering, real request
  blocking, propagation delay, provider-clock expiry with the worker stopped, and
  later cleanup. Verify both IPv4 and IPv6 where deployed.
- Use an isolated Linux VM and inert sample to verify quarantine/restoration,
  management connectivity throughout isolation, all intended interfaces/network
  namespaces, automatic release while the agent is stopped, and reboot behavior.
- Unit/integration tests use mocked HTTP/nft execution and real temporary-file
  quarantine. They establish code behavior, not live enforcement performance.
