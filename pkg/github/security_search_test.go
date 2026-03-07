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

func Test_SearchSanitization(t *testing.T) {
	maliciousTitle := "Exploit <script>alert('xss')</script>"
	maliciousBody := "Check this out <img src=x onerror=alert('xss')> and <b>bold</b>"
	sanitizedTitle := "Exploit "
	sanitizedBody := "Check this out <img src=\"x\"> and <b>bold</b>"

	mockSearchResult := &github.IssuesSearchResult{
		Total: github.Ptr(1),
		Issues: []*github.Issue{
			{
				Number: github.Ptr(1),
				Title:  github.Ptr(maliciousTitle),
				Body:   github.Ptr(maliciousBody),
			},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetSearchIssues: mockResponse(t, http.StatusOK, mockSearchResult),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}

	t.Run("search_issues sanitization", func(t *testing.T) {
		args := map[string]interface{}{
			"query": "some query",
		}

		// We need to use searchHandler directly or through a tool that uses it.
		// searchHandler is used by SearchIssues.
		result, err := searchHandler(ContextWithDeps(context.Background(), deps), deps.GetClient, args, "issue", "failed to search issues")
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedResult github.IssuesSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)

		assert.Equal(t, sanitizedTitle, *returnedResult.Issues[0].Title)
		assert.Equal(t, sanitizedBody, *returnedResult.Issues[0].Body)
	})

	t.Run("search_repositories sanitization", func(t *testing.T) {
		maliciousDesc := "Repo with <script>alert('xss')</script>"
		sanitizedDesc := "Repo with "

		mockRepoSearchResult := &github.RepositoriesSearchResult{
			Total: github.Ptr(1),
			Repositories: []*github.Repository{
				{
					ID:          github.Ptr(int64(123)),
					Name:        github.Ptr("malicious-repo"),
					Description: github.Ptr(maliciousDesc),
				},
			},
		}

		mockedRepoClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchRepositories: mockResponse(t, http.StatusOK, mockRepoSearchResult),
		})

		repoDeps := BaseDeps{
			Client: github.NewClient(mockedRepoClient),
		}

		serverTool := SearchRepositories(translations.NullTranslationHelper)
		handler := serverTool.Handler(repoDeps)

		args := map[string]interface{}{
			"query":          "malicious",
			"minimal_output": true,
		}
		request := createMCPRequest(args)

		result, err := handler(ContextWithDeps(context.Background(), repoDeps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedResult MinimalSearchRepositoriesResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)

		assert.Equal(t, sanitizedDesc, returnedResult.Items[0].Description)
	})
}
