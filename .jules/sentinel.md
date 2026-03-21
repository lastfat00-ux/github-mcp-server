## 2025-05-14 - XSS Vulnerability Pattern in User-Generated Content
**Vulnerability:** User-generated content such as titles, bodies, and comments fetched from the GitHub API were being returned to the client without sanitization, potentially leading to XSS vulnerabilities in AI interfaces.
**Learning:** In an MCP architecture, the server acts as a data provider for LLMs. Relying solely on client-side sanitization is risky; sanitization should occur at the API response layer to prevent vulnerability propagation.
**Prevention:** Always use `pkg/sanitize.Sanitize` on untrusted content (titles, bodies, comments) before returning it in MCP tool results.
