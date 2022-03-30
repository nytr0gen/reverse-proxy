# NodeJS Reverse Proxy

Made this mostly to use it with SSRF vulnerabilities for escalation. Or to MITM. Perks: Caching for static files and logging.

Start with `yarn start https://example.com:443/`

Proxy can be set with `export GLOBAL_AGENT_HTTP_PROXY=http://127.0.0.1:8080`
