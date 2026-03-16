## 2025-05-15 - GraphQL Content Sanitization Gap
**Vulnerability:** User-generated content fetched via GitHub GraphQL API (Discussions) was not sanitized, unlike content from REST API endpoints (Issues, Pull Requests).
**Learning:** Security controls applied to one API layer (REST) are often missed when implementing similar functionality in another layer (GraphQL) within the same codebase.
**Prevention:** Establish a project-wide convention that all user-contributed fields (Title, Body, Comments, Descriptions) must be sanitized at the API response layer before being returned to the MCP client.
