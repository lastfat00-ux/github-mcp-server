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

func TestActionsXSSSanitization(t *testing.T) {
	maliciousTitle := "Malicious <script>alert('xss')</script> Title"
	sanitizedTitle := "Malicious  Title"

	t.Run("GetWorkflowRun sanitization", func(t *testing.T) {
		toolDef := GetWorkflowRun(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsRunsByOwnerByRepoByRunID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				run := &github.WorkflowRun{
					ID:           github.Ptr(int64(12345)),
					Name:         github.Ptr(maliciousTitle),
					DisplayTitle: github.Ptr(maliciousTitle),
					HeadBranch:   github.Ptr(maliciousTitle),
					Status:       github.Ptr("completed"),
					Conclusion:   github.Ptr("success"),
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(run)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo", "run_id": 12345.0})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		var response github.WorkflowRun
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)
		assert.Equal(t, sanitizedTitle, *response.Name)
		assert.Equal(t, sanitizedTitle, *response.DisplayTitle)
		assert.Equal(t, sanitizedTitle, *response.HeadBranch)
	})
}
