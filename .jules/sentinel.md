## 2025-05-15 - [Missing Sanitization in Discussions and Search]
**Vulnerability:** User-generated content from GitHub Discussions and Search results was returned to the client without sanitization, potentially leading to XSS if the client renders this content without further protection.
**Learning:** While most Issue and Pull Request tools already implemented sanitization, newer or shared utility functions like `searchHandler` and Discussions tools were overlooked.
**Prevention:** Always apply `pkg/sanitize.Sanitize` to any user-contributed string fields (titles, bodies, comments) before returning them in tool results. Shared handlers must ensure they sanitize results for all types they support.
