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

func Test_ProjectsXSS(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script><b>Safe</b>"
	sanitizedPayload := "<b>Safe</b>"

	tests := []struct {
		name string
		tool func(translations.TranslationHelperFunc) inventory.ServerTool
		args map[string]any
		mock map[string]http.HandlerFunc
		validate func(t *testing.T, resultText string)
	}{
		{
			name: "ListProjects sanitizes title and description",
			tool: ListProjects,
			args: map[string]any{"owner": "org", "owner_type": "org"},
			mock: map[string]http.HandlerFunc{
				GetOrgsProjectsV2: mockResponse(t, http.StatusOK, []map[string]any{
					{
						"id": 1,
						"title": maliciousPayload,
						"description": maliciousPayload,
						"short_description": maliciousPayload,
					},
				}),
			},
			validate: func(t *testing.T, resultText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(resultText), &resp)
				require.NoError(t, err)
				projects := resp["projects"].([]any)
				project := projects[0].(map[string]any)
				assert.Equal(t, sanitizedPayload, project["title"])
				assert.Equal(t, sanitizedPayload, project["description"])
				assert.Equal(t, sanitizedPayload, project["short_description"])
			},
		},
		{
			name: "ListProjectFields sanitizes field name",
			tool: ListProjectFields,
			args: map[string]any{"owner": "org", "owner_type": "org", "project_number": 1.0},
			mock: map[string]http.HandlerFunc{
				GetOrgsProjectsV2FieldsByProject: mockResponse(t, http.StatusOK, []map[string]any{
					{
						"id": 101,
						"name": maliciousPayload,
					},
				}),
			},
			validate: func(t *testing.T, resultText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(resultText), &resp)
				require.NoError(t, err)
				fields := resp["fields"].([]any)
				field := fields[0].(map[string]any)
				assert.Equal(t, sanitizedPayload, field["name"])
			},
		},
		{
			name: "ListProjectItems sanitizes item field name and value",
			tool: ListProjectItems,
			args: map[string]any{"owner": "org", "owner_type": "org", "project_number": 1.0},
			mock: map[string]http.HandlerFunc{
				GetOrgsProjectsV2ItemsByProject: mockResponse(t, http.StatusOK, []map[string]any{
					{
						"id": 301,
						"fields": []map[string]any{
							{
								"name": maliciousPayload,
								"value": maliciousPayload,
							},
						},
					},
				}),
			},
			validate: func(t *testing.T, resultText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(resultText), &resp)
				require.NoError(t, err)
				items := resp["items"].([]any)
				item := items[0].(map[string]any)
				fields := item["fields"].([]any)
				field := fields[0].(map[string]any)
				assert.Equal(t, sanitizedPayload, field["name"])
				assert.Equal(t, sanitizedPayload, field["value"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverTool := tc.tool(translations.NullTranslationHelper)
			client := gh.NewClient(MockHTTPClientWithHandlers(tc.mock))
			deps := BaseDeps{Client: client}
			handler := serverTool.Handler(deps)

			req := createMCPRequest(tc.args)
			result, err := handler(ContextWithDeps(context.Background(), deps), &req)
			require.NoError(t, err)
			require.False(t, result.IsError)

			tc.validate(t, getTextResult(t, result).Text)
		})
	}
}
