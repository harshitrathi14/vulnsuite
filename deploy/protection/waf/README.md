# ModSecurity / OWASP CRS connector

This integration runs a real WAF at the API proxy and ships sanitised rule matches
through the existing per-host agent. It does not replace an API gateway or bypass
API authentication. No HTTP payload regexes are implemented as a substitute WAF.

1. Install a supported ModSecurity v3 build with JSON/YAJL support, its nginx
   connector and OWASP CRS on the API proxy. Use your distribution/vendor's supported
   packages. Match CRS and ModSecurity versions and keep them patched.
2. Copy `modsecurity-vulnsuite.conf` to `/etc/modsecurity/`, adjusting the base
   configuration and CRS include paths to the installation. Review CRS exclusions
   for your application and preserve existing policy if it is already stricter.
3. Create `/var/log/modsecurity/` writable by the nginx worker and grant the agent
   read access to the audit file. Keep logs private, rotate them and preserve the
   permissions across rotation. ModSecurity audit logs can contain matched data
   and URIs even with request headers/bodies omitted.
4. Add the directives in `nginx-location.conf.example` to the API's existing TLS
   server/location. Restrict trusted proxies explicitly so the client IP cannot
   be forged using arbitrary forwarded headers. Prevent direct access to backend
   servers, or callers could bypass the WAF entirely.
5. Append the object from `agent-log.example.json` to that proxy host's agent `logs`
   list. Give the proxy its own enrolled host token. Restart the agent.
6. Validate with `nginx -t`, then reload nginx in staging. Send your application's
   normal API test traffic and approved OWASP CRS test cases to the staging proxy.
   Check `operator alerts` for `waf_rule_match` and `operator hosts` for WAF sensor
   status. The agent starts at log EOF on enrollment, so generate new traffic.
7. The template starts in **DetectionOnly**. After exclusions and false positives
   are reviewed, set `SecRuleEngine On`, validate nginx configuration and reload.
   Confirm the WAF actually rejects a matching test request while normal requests
   still work. Returning the directive to DetectionOnly disables WAF intervention
   without removing telemetry. A reload is a deployment action, not performed by
   VulnSuite's source installation or unit tests.

The parser supports ModSecurity v3 **serial JSON**, one transaction per line, with
`transaction.client_ip` and `transaction.messages[].details.ruleId`. It emits only
numeric rule IDs, source address and `waf_action`. It never ships request body,
headers, URI, rule message or matched data. Records above the 64 KiB line budget
are skipped and mark the WAF sensor partial; constrain local logging accordingly.
Native/multipart or ModSecurity v2 audit logs need a normalising adapter first.

`waf_action=interrupted` requires the explicit boolean `is_interrupted=true` field.
If absent, action is `unknown`; HTTP status 403 alone never proves WAF enforcement.
Some older engines omit this field. Log readability (`sensor_status=ok`) also does
not prove the WAF is enabled or inline: verify enforcement using live staging tests.

The existing operator-requested nftables response runs on the reporting proxy host;
it is not a cloud-WAF policy API. Protect proxy/control-plane addresses from IP
blocking. A reverse proxy must see the real client as packet source for nftables
client blocks to work; for an upstream CDN/cloud WAF use that provider's response
connector instead. No cloud-WAF keys or rules have been changed by this module.

Format and deployment references:

- [ModSecurity v3 reference manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))
- [Official JSON serializer](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/transaction.cc)
- [OWASP CRS documentation](https://coreruleset.org/docs/)
