## 2025-05-15 - [XSS in Notification Titles]
**Vulnerability:** User-generated content in GitHub notification titles was not sanitized before being returned to the MCP client, potentially leading to XSS vulnerabilities in AI interfaces or tools that render these titles.
**Learning:** While the server acts as a pass-through for GitHub API data, it must treat all user-contributed fields as untrusted and sanitize them at the API response layer to prevent vulnerability propagation.
**Prevention:** Always apply `pkg/sanitize.Sanitize` to titles, bodies, and comments fetched from the GitHub API before returning them to the client.
