# Sentinel's Journal

## 2025-05-15 - HTML Sanitization for Discussions
**Vulnerability:** Untrusted user content (titles, bodies, comments) fetched from the GitHub GraphQL API for Discussions was being returned to AI interfaces without sanitization, potentially leading to XSS vulnerabilities.
**Learning:** In an MCP architecture, the server acts as a data provider for LLMs. If the server doesn't sanitize content from external APIs like GitHub, malicious HTML or scripts could be propagated to the AI's rendering interface.
**Prevention:** Always use `pkg/sanitize.Sanitize` (which uses `bluemonday`) at the API response layer to strip unsafe HTML from user-contributed content before returning it to the MCP client.
