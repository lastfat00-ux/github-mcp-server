## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2025-05-15 - Plain-text Fields vs HTML Sanitization

**Vulnerability:** Plain-text fields (like notification titles) can contain code snippets or angle brackets (e.g., `<Button />`). Applying HTML sanitization (`pkg/sanitize.Sanitize`) to plain-text fields corrupts valid developer data.

**Learning:** `pkg/sanitize.Sanitize` runs HTML tag stripping via `bluemonday`. For plain-text strings, HTML sanitization causes data loss. However, plain-text fields can still harbour invisible Unicode characters and BiDi override characters (`\u200B`, `\u202E`) used in spoofing or Trojan Source attacks.

**Prevention:** Use `pkg/sanitize.FilterInvisibleCharacters` for plain-text string fields (like notification titles) to remove control and BiDi override characters while preserving plain-text angle brackets and code samples.
