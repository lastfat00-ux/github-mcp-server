## 2025-05-22 - Sanitization in Data Providers
**Vulnerability:** User-generated content (descriptions, titles) from GitHub API was returned unsanitized, risking XSS in client-side renders.
**Learning:** In an MCP architecture, the server acts as a data provider for LLMs; relying solely on client-side sanitization is risky. Sanitization must occur at the API response layer to prevent vulnerability propagation.
**Prevention:** Always apply `pkg/sanitize.Sanitize` to untrusted user-contributed fields before returning them to the client.

## 2025-05-22 - Destructive Sanitization of Code
**Vulnerability:** Attempting to sanitize Gist file contents using HTML/character filtering logic.
**Learning:** Applying generic sanitization to source code or configuration files is destructive and corrupts the data.
**Prevention:** Distinguish between user-facing metadata (descriptions, titles) which should be sanitized, and technical content (file data, code) which must remain intact.
