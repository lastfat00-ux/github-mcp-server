## 2025-05-15 - Unsanitized User Content in MCP Responses
**Vulnerability:** User-generated content (titles, bodies, comments) fetched from the GitHub API was being returned to MCP clients without HTML sanitization.
**Learning:** In an MCP architecture, the server acts as a data provider for LLMs. Relying solely on client-side sanitization is risky as LLMs might process or re-render this content in various contexts (web UIs, IDEs). Sanitizing at the API response layer prevents vulnerability propagation.
**Prevention:** Use `pkg/sanitize.Sanitize` on all untrusted user content (titles, bodies, descriptions, comments) before returning results to the client.
