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

func Test_GistsXSSSanitization(t *testing.T) {
	maliciousDescription := "Malicious <script>alert('xss')</script> description"
	expectedSanitizedDescription := "Malicious  description"

	mockGist := &github.Gist{
		ID:          github.Ptr("gist123"),
		Description: github.Ptr(maliciousDescription),
	}

	tests := []struct {
		name         string
		toolFactory  func(translations.TranslationHelperFunc) inventory.ServerTool
		mockPath     string
		requestArgs  map[string]any
		isList       bool
	}{
		{
			name:        "ListGists sanitizes description",
			toolFactory: ListGists,
			mockPath:    GetGists,
			requestArgs: map[string]any{},
			isList:      true,
		},
		{
			name:        "GetGist sanitizes description",
			toolFactory: GetGist,
			mockPath:    GetGistsByGistID,
			requestArgs: map[string]any{"gist_id": "gist123"},
			isList:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var handler http.HandlerFunc
			if tc.isList {
				handler = mockResponse(t, http.StatusOK, []*github.Gist{mockGist})
			} else {
				handler = mockResponse(t, http.StatusOK, mockGist)
			}

			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.mockPath: handler,
			})

			client := github.NewClient(mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			serverTool := tc.toolFactory(translations.NullTranslationHelper)
			toolHandler := serverTool.Handler(deps)

			request := createMCPRequest(tc.requestArgs)
			result, err := toolHandler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			require.False(t, result.IsError)

			textContent := getTextResult(t, result)

			if tc.isList {
				var gists []*github.Gist
				err = json.Unmarshal([]byte(textContent.Text), &gists)
				require.NoError(t, err)
				require.Len(t, gists, 1)
				assert.Equal(t, expectedSanitizedDescription, *gists[0].Description)
			} else {
				var gist github.Gist
				err = json.Unmarshal([]byte(textContent.Text), &gist)
				require.NoError(t, err)
				assert.Equal(t, expectedSanitizedDescription, *gist.Description)
			}
		})
	}
}
