## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2025-05-16 - Rejected Sanitization on Security Advisory Fields

**Vulnerability:** Attempted HTML/XSS sanitization on Dependabot alerts and Security Advisory metadata (such as CVE summaries or exploit descriptions).

**Learning:** Running an HTML/XSS sanitizer on technical vulnerability fields (like `Summary` or `Description`) in security advisories actively destroys essential proof-of-concept (PoC) exploit payloads (e.g., `<script>alert(1)</script>`). Developers and LLMs need these payloads intact to analyze and remediate security vulnerabilities. While descriptive social text (like user-written titles and comments) must be sanitized, technical vulnerability definitions must be preserved without loss of data.

**Prevention:** Only sanitize human/social text fields (e.g., notification titles, issue comments) and avoid sanitizing advisory descriptions or CVE payloads to prevent information loss.
