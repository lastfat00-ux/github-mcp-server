package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActions_Security(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script>SafeName"
	expectedSanitized := "SafeName"

	t.Run("ListWorkflows sanitization", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsWorkflowsByOwnerByRepo: func(w http.ResponseWriter, r *http.Request) {
				workflows := &github.Workflows{
					TotalCount: github.Ptr(1),
					Workflows: []*github.Workflow{
						{
							Name: github.Ptr(maliciousPayload),
						},
					},
				}
				json.NewEncoder(w).Encode(workflows)
			},
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		tool := ListWorkflows(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo"})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		assert.NotContains(t, textContent.Text, "<script>")
		assert.Contains(t, textContent.Text, expectedSanitized)
	})

	t.Run("ActionsList list_workflows sanitization", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsWorkflowsByOwnerByRepo: func(w http.ResponseWriter, r *http.Request) {
				workflows := &github.Workflows{
					TotalCount: github.Ptr(1),
					Workflows: []*github.Workflow{
						{
							Name: github.Ptr(maliciousPayload),
						},
					},
				}
				json.NewEncoder(w).Encode(workflows)
			},
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		tool := ActionsList(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		request := createMCPRequest(map[string]any{
			"method": "list_workflows",
			"owner":  "owner",
			"repo":   "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		assert.NotContains(t, textContent.Text, "<script>")
		assert.Contains(t, textContent.Text, expectedSanitized)
	})
}
