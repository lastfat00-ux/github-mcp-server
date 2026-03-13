## 2025-05-15 - Inconsistent Sanitization of User-Generated Content
**Vulnerability:** User-generated content from GitHub (titles, bodies, comments) in the Discussions toolset was missing XSS sanitization, unlike Issues and Pull Requests.
**Learning:** In an MCP architecture, the server acts as a data provider for LLMs. If the server doesn't sanitize untrusted content, it can propagate vulnerabilities to the final rendering client. Relying solely on client-side sanitization is risky; defense in depth requires sanitization at the API response layer.
**Prevention:** Always apply `pkg/sanitize.Sanitize` to any user-contributed string field fetched from external APIs (GitHub) before including it in the tool output. Standardize this pattern across all toolsets.
