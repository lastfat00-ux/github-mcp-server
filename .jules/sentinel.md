## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2025-05-22 - XSS in GitHub Discussion Category Names
**Vulnerability:** Discussion category names fetched from the GitHub GraphQL API were not sanitized, allowing for potential XSS if a repository administrator sets a malicious category name.
**Learning:** While major fields like discussion titles and bodies were already sanitized, secondary metadata fields like category names were overlooked. Security sanitization must be applied to all user-controllable string fields returned by the MCP server.
**Prevention:** Always apply `sanitize.Sanitize` to all string fields originating from untrusted user input, including metadata like labels and categories, before returning them in tool results.
