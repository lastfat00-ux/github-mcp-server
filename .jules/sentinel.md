## 2025-05-13 - [Regression] Missing Sanitization in Notifications
**Vulnerability:** Notification subject titles were being returned without sanitization, allowing for potential XSS in MCP clients.
**Learning:** Even when sanitization utilities exist (like pkg/sanitize), they must be consistently applied to all new or overlooked data paths. MCP servers act as data providers for AI interfaces, making server-side sanitization critical.
**Prevention:** Consistently apply sanitization to all user-controllable string fields in API responses. Use unit tests with malicious payloads to verify sanitization logic.
