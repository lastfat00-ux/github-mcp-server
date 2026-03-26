## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2026-03-26 - XSS in Notification Subject Titles
**Vulnerability:** GitHub Notification subject titles were not being sanitized, unlike Issue and PR bodies.
**Learning:** Security audits must trace all possible data paths. It's easy to miss metadata-like fields (subjects, titles) when the primary focus is on large content fields (bodies).
**Prevention:** Apply consistent sanitization to all user-provided strings in API responses, including titles and subjects.
