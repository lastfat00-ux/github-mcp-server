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

func TestRepositoriesSecurity(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script><b>Safe</b>"

	t.Run("get_commit sanitizes message", func(t *testing.T) {
		serverTool := GetCommit(translations.NullTranslationHelper)
		mockCommit := &github.RepositoryCommit{
			SHA: github.Ptr("sha123"),
			Commit: &github.Commit{
				Message: github.Ptr(maliciousPayload),
			},
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCommitsByOwnerByRepoByRef: mockResponse(t, http.StatusOK, mockCommit),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo": "repo",
			"sha": "sha123",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res MinimalCommit
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, res.Commit.Message, "<script>")
	})

	t.Run("search_repositories sanitizes description", func(t *testing.T) {
		serverTool := SearchRepositories(translations.NullTranslationHelper)
		mockResult := &github.RepositoriesSearchResult{
			Total: github.Ptr(1),
			Repositories: []*github.Repository{
				{
					ID:          github.Ptr(int64(1)),
					Name:        github.Ptr("repo"),
					Description: github.Ptr(maliciousPayload),
				},
			},
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetSearchRepositories: mockResponse(t, http.StatusOK, mockResult),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"query": "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res MinimalSearchRepositoriesResult
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, res.Items[0].Description, "<script>")
	})

	t.Run("list_starred_repositories sanitizes description", func(t *testing.T) {
		serverTool := ListStarredRepositories(translations.NullTranslationHelper)
		mockStarred := []*github.StarredRepository{
			{
				Repository: &github.Repository{
					ID:          github.Ptr(int64(1)),
					Name:        github.Ptr("repo"),
					Description: github.Ptr(maliciousPayload),
				},
			},
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetUserStarred: mockResponse(t, http.StatusOK, mockStarred),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res []MinimalRepository
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, res[0].Description, "<script>")
	})

	t.Run("list_releases sanitizes name and body", func(t *testing.T) {
		serverTool := ListReleases(translations.NullTranslationHelper)
		mockReleases := []*github.RepositoryRelease{
			{
				ID:      github.Ptr(int64(1)),
				TagName: github.Ptr("v1"),
				Name:    github.Ptr(maliciousPayload),
				Body:    github.Ptr(maliciousPayload),
			},
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposReleasesByOwnerByRepo: mockResponse(t, http.StatusOK, mockReleases),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo": "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res []*github.RepositoryRelease
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, *res[0].Name, "<script>")
		assert.NotContains(t, *res[0].Body, "<script>")
	})

	t.Run("get_latest_release sanitizes name and body", func(t *testing.T) {
		serverTool := GetLatestRelease(translations.NullTranslationHelper)
		mockRelease := &github.RepositoryRelease{
			ID:      github.Ptr(int64(1)),
			TagName: github.Ptr("v1"),
			Name:    github.Ptr(maliciousPayload),
			Body:    github.Ptr(maliciousPayload),
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposReleasesLatestByOwnerByRepo: mockResponse(t, http.StatusOK, mockRelease),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo": "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res github.RepositoryRelease
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, *res.Name, "<script>")
		assert.NotContains(t, *res.Body, "<script>")
	})

	t.Run("get_release_by_tag sanitizes name and body", func(t *testing.T) {
		serverTool := GetReleaseByTag(translations.NullTranslationHelper)
		mockRelease := &github.RepositoryRelease{
			ID:      github.Ptr(int64(1)),
			TagName: github.Ptr("v1"),
			Name:    github.Ptr(maliciousPayload),
			Body:    github.Ptr(maliciousPayload),
		}
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposReleasesTagsByOwnerByRepoByTag: mockResponse(t, http.StatusOK, mockRelease),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo": "repo",
			"tag": "v1",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var res github.RepositoryRelease
		err = json.Unmarshal([]byte(textContent.Text), &res)
		require.NoError(t, err)
		assert.NotContains(t, *res.Name, "<script>")
		assert.NotContains(t, *res.Body, "<script>")
	})
}
