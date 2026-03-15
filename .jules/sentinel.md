# Sentinel's Journal - Critical Security Learnings

## 2025-05-23 - API Layer Sanitization for LLM Data Providers
**Vulnerability:** Potential XSS propagation through user-contributed content (titles, bodies, comments) in an MCP server environment.
**Learning:** In a Model Context Protocol (MCP) architecture, the server provides data to LLMs which then present it to users. Relying solely on client-side UI sanitization is insufficient because malicious user content fetched from external APIs (like GitHub) can bypass traditional UI protections or be misinterpreted by the LLM itself. Sanitizing untrusted content at the server's API response layer ensures that all downstream consumers (LLMs and their respective UIs) receive "safe" data by default.
**Prevention:** Always apply a sanitization utility like `pkg/sanitize.Sanitize` to user-contributed fields (e.g., titles, descriptions, comments) before returning them in an MCP tool result. Be aware of the trade-off where technical content resembling HTML tags (e.g., `List<String>`) may be filtered, and document this behavior in the code.
