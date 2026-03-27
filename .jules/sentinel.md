## 2025-05-15 - XSS via Untrusted GitHub Content in MCP Server

**Vulnerability:** Untrusted user-generated content (titles, bodies, comments) fetched from the GitHub API can contain malicious HTML/script tags. If an MCP server returns this content unsanitized, it can propagate XSS vulnerabilities to AI interfaces or other downstream clients.

**Learning:** While many web applications rely on client-side sanitization, an MCP server acts as a data provider for LLMs and various tools. Relying solely on client-side sanitization is risky because the rendering context of an LLM's output is not always known or secure. Sanitization must occur at the API response layer within the MCP server.

**Prevention:** Always use `pkg/sanitize.Sanitize` on any untrusted string content fetched from external APIs (like GitHub Issues, PRs, and Discussions) before returning it in a tool result.

## 2026-03-27 - CI Linter Failures due to Outdated Configuration
**Vulnerability:** Not a direct application vulnerability, but a security process failure. Using an outdated and panicking linter in CI effectively disables automated security checks (like `gosec`), allowing vulnerabilities to bypass the gated pipeline unnoticed.

**Learning:** CI configuration and linter versions must be kept current with the project's Go version. Hardcoding ancient linter versions (e.g., `v2.5` when the project is Go 1.24+) leads to brittle CI and potential security gaps if the checks fail silently or crash.

**Prevention:** Use `go-version-file: "go.mod"` in CI workflows to ensure environment consistency. Avoid pinning linters to extremely old versions; rely on modern Action versions that auto-detect or allow standard versioning. Periodically audit CI logs for "hidden" failures like linter panics.
