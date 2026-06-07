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

func Test_SearchSecurity(t *testing.T) {
	t.Run("search_repositories sanitizes description", func(t *testing.T) {
		mockSearchResult := &github.RepositoriesSearchResult{
			Total: github.Ptr(1),
			Repositories: []*github.Repository{
				{
					ID:          github.Ptr(int64(123)),
					Name:        github.Ptr("malicious-repo"),
					FullName:    github.Ptr("owner/malicious-repo"),
					Description: github.Ptr("Normal <script>alert('xss')</script>Description"),
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchRepositories: mockResponse(t, http.StatusOK, mockSearchResult),
		})

		client := github.NewClient(mockedClient)
		serverTool := SearchRepositories(translations.NullTranslationHelper)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		// Test minimal output
		args := map[string]interface{}{
			"query":          "test",
			"minimal_output": true,
		}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var minimalResult MinimalSearchRepositoriesResult
		err = json.Unmarshal([]byte(textContent.Text), &minimalResult)
		require.NoError(t, err)
		assert.Equal(t, "Normal Description", minimalResult.Items[0].Description)

		// Test full output
		args["minimal_output"] = false
		request = createMCPRequest(args)
		result, err = handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent = getTextResult(t, result)
		var fullResult github.RepositoriesSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &fullResult)
		require.NoError(t, err)
		assert.Equal(t, "Normal Description", *fullResult.Repositories[0].Description)
	})

	t.Run("search_code sanitizes repository description but NOT fragments", func(t *testing.T) {
		fragment := "func main() { <script>alert('xss')</script> }"
		mockSearchResult := &github.CodeSearchResult{
			Total: github.Ptr(1),
			CodeResults: []*github.CodeResult{
				{
					Name: github.Ptr("test.go"),
					Path: github.Ptr("test.go"),
					TextMatches: []*github.TextMatch{
						{
							Fragment: github.Ptr(fragment),
						},
					},
					Repository: &github.Repository{
						FullName:    github.Ptr("owner/repo"),
						Description: github.Ptr("Repo <script>alert('xss')</script>Description"),
					},
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchCode: mockResponse(t, http.StatusOK, mockSearchResult),
		})

		client := github.NewClient(mockedClient)
		serverTool := SearchCode(translations.NullTranslationHelper)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		args := map[string]interface{}{"query": "test"}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var codeResult github.CodeSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &codeResult)
		require.NoError(t, err)
		// Fragments should be preserved as they are technical content
		assert.Equal(t, fragment, *codeResult.CodeResults[0].TextMatches[0].Fragment)
		// Repository descriptions should be sanitized
		assert.Equal(t, "Repo Description", *codeResult.CodeResults[0].Repository.Description)
	})

	t.Run("search_issues sanitizes title, body and repository description", func(t *testing.T) {
		mockSearchResult := &github.IssuesSearchResult{
			Total: github.Ptr(1),
			Issues: []*github.Issue{
				{
					ID:    github.Ptr(int64(1)),
					Title: github.Ptr("Malicious <script>alert('xss')</script>Title"),
					Body:  github.Ptr("Malicious <script>alert('xss')</script>Body"),
					Repository: &github.Repository{
						FullName:    github.Ptr("owner/repo"),
						Description: github.Ptr("Repo <script>alert('xss')</script>Description"),
					},
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchIssues: mockResponse(t, http.StatusOK, mockSearchResult),
		})

		client := github.NewClient(mockedClient)
		serverTool := SearchIssues(translations.NullTranslationHelper)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		args := map[string]interface{}{"query": "test"}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var issuesResult github.IssuesSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &issuesResult)
		require.NoError(t, err)
		assert.Equal(t, "Malicious Title", *issuesResult.Issues[0].Title)
		assert.Equal(t, "Malicious Body", *issuesResult.Issues[0].Body)
		assert.Equal(t, "Repo Description", *issuesResult.Issues[0].Repository.Description)
	})

	t.Run("search_pull_requests sanitizes title, body and repository description", func(t *testing.T) {
		mockSearchResult := &github.IssuesSearchResult{
			Total: github.Ptr(1),
			Issues: []*github.Issue{
				{
					ID:    github.Ptr(int64(2)),
					Title: github.Ptr("Malicious <script>alert('xss')</script>PR Title"),
					Body:  github.Ptr("Malicious <script>alert('xss')</script>PR Body"),
					Repository: &github.Repository{
						FullName:    github.Ptr("owner/repo"),
						Description: github.Ptr("Repo <script>alert('xss')</script>Description"),
					},
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchIssues: mockResponse(t, http.StatusOK, mockSearchResult),
		})

		client := github.NewClient(mockedClient)
		serverTool := SearchPullRequests(translations.NullTranslationHelper)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		args := map[string]interface{}{"query": "test"}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var prResult github.IssuesSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &prResult)
		require.NoError(t, err)
		assert.Equal(t, "Malicious PR Title", *prResult.Issues[0].Title)
		assert.Equal(t, "Malicious PR Body", *prResult.Issues[0].Body)
		assert.Equal(t, "Repo Description", *prResult.Issues[0].Repository.Description)
	})
}
