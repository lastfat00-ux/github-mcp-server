## 2025-05-14 - Content Injection in LLM Interfaces via MCP
**Vulnerability:** Untrusted user-generated content (e.g., notification titles, issue bodies) fetched from external APIs (GitHub) can contain malicious payloads (HTML/JS) that may be rendered unsafely by LLM client interfaces.
**Learning:** In an MCP architecture, the server acts as a data provider. While standard web apps sanitize on the frontend, MCP servers should provide "clean" data at the API response layer to protect diverse and potentially naive AI client implementations.
**Prevention:** Always use `pkg/sanitize.Sanitize` (or equivalent) on user-contributed fields before returning them in MCP tool results. This creates a "defense in depth" layer at the source of the data.
