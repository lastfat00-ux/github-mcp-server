package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	gh "github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssues_XSSSanitization(t *testing.T) {
	maliciousBody := "Malicious Body <script>alert('xss')</script>"
	sanitizedBody := "Malicious Body "

	comment := map[string]any{
		"id":   1,
		"body": maliciousBody,
		"user": map[string]any{"login": "octocat"},
	}

	tests := []struct {
		name        string
		requestArgs map[string]any
	}{
		{
			name: "GetIssueComments",
			requestArgs: map[string]any{
				"method":       "get_comments",
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(1),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, []any{comment}),
			})

			client := gh.NewClient(mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			serverTool := IssueRead(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)
			request := createMCPRequest(tc.requestArgs)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			require.False(t, result.IsError)

			textContent := getTextResult(t, result)
			var results []map[string]any
			err = json.Unmarshal([]byte(textContent.Text), &results)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, sanitizedBody, results[0]["body"])
		})
	}
}
