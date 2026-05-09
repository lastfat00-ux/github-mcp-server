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

func Test_GistsSanitization(t *testing.T) {
	maliciousDescription := "Gist with <script>alert('xss')</script> description"
	expectedDescription := "Gist with  description"

	mockGist := &gh.Gist{
		ID:          gh.String("gist123"),
		Description: gh.String(maliciousDescription),
		HTMLURL:     gh.String("https://gist.github.com/user/gist123"),
	}

	t.Run("ListGists sanitizes description", func(t *testing.T) {
		mockClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetGists: mockResponse(t, http.StatusOK, []*gh.Gist{mockGist}),
		})

		serverTool := ListGists(translations.NullTranslationHelper)
		deps := BaseDeps{Client: gh.NewClient(mockClient)}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]interface{}{})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedGists []*gh.Gist
		err = json.Unmarshal([]byte(textContent.Text), &returnedGists)
		require.NoError(t, err)

		assert.Equal(t, expectedDescription, *returnedGists[0].Description)
	})

	t.Run("GetGist sanitizes description", func(t *testing.T) {
		mockClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetGistsByGistID: mockResponse(t, http.StatusOK, mockGist),
		})

		serverTool := GetGist(translations.NullTranslationHelper)
		deps := BaseDeps{Client: gh.NewClient(mockClient)}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]interface{}{"gist_id": "gist123"})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedGist gh.Gist
		err = json.Unmarshal([]byte(textContent.Text), &returnedGist)
		require.NoError(t, err)

		assert.Equal(t, expectedDescription, *returnedGist.Description)
	})
}
