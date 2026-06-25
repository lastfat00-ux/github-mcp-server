package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SearchSecuritySanitization(t *testing.T) {
	maliciousTitle := "Malicious Title <script>alert('XSS')</script>"
	maliciousBody := "Malicious Body <img src=x onerror=alert('XSS')>"
	expectedSanitizedTitle := "Malicious Title "
	expectedSanitizedBody := "Malicious Body <img src=\"x\">"

	mockIssuesSearchResult := &github.IssuesSearchResult{
		Total: github.Ptr(1),
		Issues: []*github.Issue{
			{
				ID:    github.Ptr(int64(1)),
				Title: github.Ptr(maliciousTitle),
				Body:  github.Ptr(maliciousBody),
			},
		},
	}

	tests := []struct {
		name       string
		toolGetter func(translations.TranslationHelperFunc) inventory.ServerTool
		endpoint   string
	}{
		{
			name:       "search_issues sanitization",
			toolGetter: SearchIssues,
			endpoint:   GetSearchIssues,
		},
		{
			name:       "search_pull_requests sanitization",
			toolGetter: SearchPullRequests,
			endpoint:   GetSearchIssues, // Both use /search/issues
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.endpoint: mockResponse(t, http.StatusOK, mockIssuesSearchResult),
			})

			client := github.NewClient(mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			serverTool := tc.toolGetter(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)

			request := createMCPRequest(map[string]interface{}{
				"query": "test",
			})

			result, err := handler(ContextWithDeps(context.Background(), deps), &request)
			require.NoError(t, err)
			require.False(t, result.IsError)

			textContent := getTextResult(t, result)
			var returned github.IssuesSearchResult
			err = json.Unmarshal([]byte(textContent.Text), &returned)
			require.NoError(t, err)

			require.Len(t, returned.Issues, 1)
			assert.Equal(t, expectedSanitizedTitle, *returned.Issues[0].Title, "Title should be sanitized")
			assert.Equal(t, expectedSanitizedBody, *returned.Issues[0].Body, "Body should be sanitized")
		})
	}
}

func Test_SearchRepositoriesSecuritySanitization(t *testing.T) {
	maliciousDescription := "Malicious Description <script>alert('XSS')</script>"
	expectedSanitizedDescription := "Malicious Description "

	mockReposSearchResult := &github.RepositoriesSearchResult{
		Total: github.Ptr(1),
		Repositories: []*github.Repository{
			{
				ID:          github.Ptr(int64(1)),
				Name:        github.Ptr("test-repo"),
				Description: github.Ptr(maliciousDescription),
			},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetSearchRepositories: mockResponse(t, http.StatusOK, mockReposSearchResult),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}
	serverTool := SearchRepositories(translations.NullTranslationHelper)
	handler := serverTool.Handler(deps)

	request := createMCPRequest(map[string]interface{}{
		"query": "test",
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var returned MinimalSearchRepositoriesResult
	err = json.Unmarshal([]byte(textContent.Text), &returned)
	require.NoError(t, err)

	require.Len(t, returned.Items, 1)
	assert.Equal(t, expectedSanitizedDescription, returned.Items[0].Description, "Description should be sanitized")
}
