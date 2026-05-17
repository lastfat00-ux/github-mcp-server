## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2026-05-17 - Missing Lockdown Mode Enforcement in Discussions

**Vulnerability:** GitHub Discussions lacked "Lockdown Mode" enforcement, unlike Issues and Pull Requests. This allowed the server to potentially surface content from untrusted authors in public repositories even when Lockdown Mode was enabled to mitigate risks.

**Learning:** When implementing cross-cutting security features like Lockdown Mode or XSS sanitization, it's crucial to audit all similar entities (Issues, PRs, Discussions) to ensure consistent protection across the entire application surface. Missing one category creates a security gap.

**Prevention:** Maintain a checklist of all user-generated content providers and ensure security filters (Access Control, Sanitization) are applied uniformly to all of them. Use shared helper functions or common interfaces where possible to reduce implementation gaps.
