package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	gh "github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ProjectsSecurity(t *testing.T) {
	maliciousTitle := "Project <script>alert('xss')</script>"
	expectedTitle := "Project "
	maliciousDesc := "Description <img src=x onerror=alert(1)>"
	expectedDesc := "Description <img src=\"x\">"

	tests := []struct {
		name         string
		tool         func(translations.TranslationHelperFunc) inventory.ServerTool
		mockPath     string
		mockResponse any
		requestArgs  map[string]any
		verify       func(t *testing.T, text string)
	}{
		{
			name:     "ListProjects sanitization",
			tool:     ListProjects,
			mockPath: GetOrgsProjectsV2,
			mockResponse: []map[string]any{
				{"id": 1, "title": maliciousTitle, "description": maliciousDesc, "short_description": maliciousTitle},
			},
			requestArgs: map[string]any{"owner": "org", "owner_type": "org"},
			verify: func(t *testing.T, text string) {
				var resp map[string]any
				require.NoError(t, json.Unmarshal([]byte(text), &resp))
				projects := resp["projects"].([]any)
				p := projects[0].(map[string]any)
				assert.Equal(t, expectedTitle, p["title"])
				assert.Equal(t, expectedDesc, p["description"])
				assert.Equal(t, expectedTitle, p["short_description"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.mockPath: mockResponse(t, http.StatusOK, tc.mockResponse),
			})
			client := gh.NewClient(mockedClient)
			deps := BaseDeps{Client: client}
			serverTool := tc.tool(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)
			request := createMCPRequest(tc.requestArgs)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)
			require.NoError(t, err)
			require.False(t, result.IsError)
			tc.verify(t, getTextResult(t, result).Text)
		})
	}
}
