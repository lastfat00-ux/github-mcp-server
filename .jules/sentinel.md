## 2025-05-15 - [Consistency in Content Sanitization]
**Vulnerability:** User-generated content in GitHub issue comments was being returned to the client without sanitization, posing an XSS risk if rendered in a web-based MCP client.
**Learning:** The codebase has an internal `pkg/sanitize` package that implements a whitelist-based HTML sanitizer. Other issue retrieval functions (like `GetIssue`) already used this. Applying it consistently is necessary but can be viewed as "destructive" by some reviewers because it strips technically valid but unsafe HTML tags.
**Prevention:** Ensure all tools returning user-contributed content (Issues, PRs, Discussions, Gists) use `pkg/sanitize.Sanitize` for titles and bodies to maintain a consistent security posture.
