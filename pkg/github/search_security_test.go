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

func Test_SearchSecuritySanitization(t *testing.T) {
	maliciousTitle := "Malicious Title <script>alert('xss')</script>"
	maliciousBody := "Malicious Body <img src=x onerror=alert('xss')>"
	maliciousDescription := "Malicious Description <iframe src='javascript:alert(1)'></iframe>"
	maliciousLogin := "malicious-user <svg/onload=alert(1)>"
	maliciousPath := "path/to/<script>alert(1)</script>/file.go"
	maliciousName := "file <img src=x onerror=alert(1)>.go"

	sanitizedTitle := "Malicious Title "
	sanitizedBody := "Malicious Body <img src=\"x\">"
	sanitizedDescription := "Malicious Description "
	sanitizedLogin := "malicious-user "
	sanitizedPath := "path/to//file.go"
	sanitizedName := "file <img src=\"x\">.go"

	t.Run("search_repositories sanitization", func(t *testing.T) {
		mockSearchResult := &github.RepositoriesSearchResult{
			Total:             github.Ptr(1),
			IncompleteResults: github.Ptr(false),
			Repositories: []*github.Repository{
				{
					ID:          github.Ptr(int64(1)),
					Name:        github.Ptr("repo"),
					FullName:    github.Ptr("owner/repo"),
					Description: github.Ptr(maliciousDescription),
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

		args := map[string]interface{}{"query": "test", "minimal_output": true}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)
		var returnedResult MinimalSearchRepositoriesResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)
		assert.Equal(t, sanitizedDescription, returnedResult.Items[0].Description)
	})

	t.Run("search_code sanitization", func(t *testing.T) {
		mockSearchResult := &github.CodeSearchResult{
			Total:             github.Ptr(1),
			IncompleteResults: github.Ptr(false),
			CodeResults: []*github.CodeResult{
				{
					Name:       github.Ptr(maliciousName),
					Path:       github.Ptr(maliciousPath),
					SHA:        github.Ptr("sha"),
					Repository: &github.Repository{FullName: github.Ptr("owner/repo")},
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
		textContent := getTextResult(t, result)
		var returnedResult github.CodeSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)
		assert.Equal(t, sanitizedName, *returnedResult.CodeResults[0].Name)
		assert.Equal(t, sanitizedPath, *returnedResult.CodeResults[0].Path)
	})

	t.Run("search_users sanitization", func(t *testing.T) {
		mockSearchResult := &github.UsersSearchResult{
			Total:             github.Ptr(1),
			IncompleteResults: github.Ptr(false),
			Users: []*github.User{
				{
					Login: github.Ptr(maliciousLogin),
					ID:    github.Ptr(int64(1)),
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchUsers: mockResponse(t, http.StatusOK, mockSearchResult),
		})

		client := github.NewClient(mockedClient)
		serverTool := SearchUsers(translations.NullTranslationHelper)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		args := map[string]interface{}{"query": "test"}
		request := createMCPRequest(args)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)
		var returnedResult MinimalSearchUsersResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)
		assert.Equal(t, sanitizedLogin, returnedResult.Items[0].Login)
	})

	t.Run("search_issues sanitization", func(t *testing.T) {
		mockSearchResult := &github.IssuesSearchResult{
			Total:             github.Ptr(1),
			IncompleteResults: github.Ptr(false),
			Issues: []*github.Issue{
				{
					ID:     github.Ptr(int64(1)),
					Title:  github.Ptr(maliciousTitle),
					Body:   github.Ptr(maliciousBody),
					Number: github.Ptr(1),
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
		textContent := getTextResult(t, result)
		var returnedResult github.IssuesSearchResult
		err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
		require.NoError(t, err)
		assert.Equal(t, sanitizedTitle, *returnedResult.Issues[0].Title)
		assert.Equal(t, sanitizedBody, *returnedResult.Issues[0].Body)
	})
}
