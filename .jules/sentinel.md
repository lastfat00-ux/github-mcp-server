# Sentinel's Journal

## 2025-05-14 - Inconsistent Output Sanitization
**Vulnerability:** User-generated content (titles, bodies, comments) from GitHub was inconsistently sanitized across different MCP tools, leading to XSS risks in clients that render the output.
**Learning:** While some core tools like `get_issue` and `get_pull_request` implemented sanitization, shared utilities like `searchHandler` and specialized tools like `get_issue_comments` were overlooked. This highlights the risk of "security by whack-a-mole" when sanitization is applied at the handler level instead of a more central layer.
**Prevention:** Always verify that any new tool returning user-contributed content (Issue/PR/Gist/Discussion) applies the `pkg/sanitize.Sanitize` utility. Consider moving sanitization to a shared middleware or response decorator if the architecture permits.
