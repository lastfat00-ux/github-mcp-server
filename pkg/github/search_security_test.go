package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
)

func TestXSS(t *testing.T) {
	mal, sanitized := "<script>alert(1)</script>", ""

	t.Run("SearchRepos", func(t *testing.T) {
		mockRes := &github.RepositoriesSearchResult{Total: github.Ptr(1), Repositories: []*github.Repository{{ID: github.Ptr(int64(1)), Description: github.Ptr(mal)}}}
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{GetSearchRepositories: mockResponse(t, http.StatusOK, mockRes)}))
		deps := BaseDeps{Client: client}
		ctx := ContextWithDeps(context.Background(), deps)
		st := SearchRepositories(translations.NullTranslationHelper)
		h := st.Handler(deps)

		res, _ := h(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"query":"a"}`)}})
		var minRes MinimalSearchRepositoriesResult
		json.Unmarshal([]byte(getTextResult(t, res).Text), &minRes)
		assert.Equal(t, sanitized, minRes.Items[0].Description)

		res, _ = h(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"query":"a","minimal_output":false}`)}})
		var fullRes github.RepositoriesSearchResult
		json.Unmarshal([]byte(getTextResult(t, res).Text), &fullRes)
		assert.Equal(t, sanitized, *fullRes.Repositories[0].Description)
	})

	t.Run("searchHandler", func(t *testing.T) {
		mockRes := &github.IssuesSearchResult{Total: github.Ptr(1), Issues: []*github.Issue{{ID: github.Ptr(int64(1)), Title: github.Ptr("I "+mal), Body: github.Ptr(mal)}}}
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{GetSearchIssues: mockResponse(t, http.StatusOK, mockRes)}))
		res, _ := searchHandler(context.Background(), func(context.Context) (*github.Client, error) { return client, nil }, map[string]any{"query": "a"}, "issue", "err")
		var out github.IssuesSearchResult
		json.Unmarshal([]byte(getTextResult(t, res).Text), &out)
		assert.Equal(t, "I ", *out.Issues[0].Title)
		assert.Equal(t, sanitized, *out.Issues[0].Body)
	})

	t.Run("StarredRepos", func(t *testing.T) {
		mockRes := []*github.StarredRepository{{Repository: &github.Repository{ID: github.Ptr(int64(1)), Description: github.Ptr(mal)}}}
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{GetUserStarred: mockResponse(t, http.StatusOK, mockRes)}))
		deps := BaseDeps{Client: client}
		ctx := ContextWithDeps(context.Background(), deps)
		st := ListStarredRepositories(translations.NullTranslationHelper)
		h := st.Handler(deps)
		res, _ := h(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)}})
		var minRes []MinimalRepository
		json.Unmarshal([]byte(getTextResult(t, res).Text), &minRes)
		assert.Equal(t, sanitized, minRes[0].Description)
	})

	t.Run("MinimalCommit", func(t *testing.T) {
		min := convertToMinimalCommit(&github.RepositoryCommit{Commit: &github.Commit{Message: github.Ptr(mal)}}, false)
		assert.Equal(t, sanitized, min.Commit.Message)
	})
}
