## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2025-05-20 - XSS via Notification Subject Titles
**Vulnerability:** Notification subject titles fetched from the GitHub API were not sanitized, allowing malicious HTML/script tags to be passed to MCP clients.
**Learning:** Security audits must trace metadata-like fields (subjects, titles) as they often represent distinct data paths from primary content (bodies/comments) and can be overlooked in broad sanitization sweeps.
**Prevention:** Ensure all user-contributed fields, including titles and subjects, are passed through `pkg/sanitize.Sanitize` at the API response layer.
