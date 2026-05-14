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

func Test_Projects_Security(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script>Malicious"
	expectedSanitized := "Malicious"

	tests := []struct {
		name         string
		toolFactory  func(translations.TranslationHelperFunc) inventory.ServerTool
		method       string
		mockPath     string
		mockData     any
		requestArgs  map[string]any
		validateFunc func(t *testing.T, responseText string)
	}{
		{
			name:        "ListProjects sanitizes title and description",
			toolFactory: ListProjects,
			mockPath:    GetOrgsProjectsV2,
			mockData: []map[string]any{{
				"id":                1,
				"title":             maliciousPayload,
				"description":       maliciousPayload,
				"short_description": maliciousPayload,
			}},
			requestArgs: map[string]any{
				"owner":      "octo-org",
				"owner_type": "org",
			},
			validateFunc: func(t *testing.T, responseText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(responseText), &resp)
				require.NoError(t, err)
				projects := resp["projects"].([]any)
				project := projects[0].(map[string]any)
				assert.Equal(t, expectedSanitized, project["title"])
				assert.Equal(t, expectedSanitized, project["description"])
				assert.Equal(t, expectedSanitized, project["short_description"])
			},
		},
		{
			name:        "ListProjectFields sanitizes field name",
			toolFactory: ListProjectFields,
			mockPath:    GetOrgsProjectsV2FieldsByProject,
			mockData: []map[string]any{{
				"id":   101,
				"name": maliciousPayload,
			}},
			requestArgs: map[string]any{
				"owner":          "octo-org",
				"owner_type":     "org",
				"project_number": float64(123),
			},
			validateFunc: func(t *testing.T, responseText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(responseText), &resp)
				require.NoError(t, err)
				fields := resp["fields"].([]any)
				field := fields[0].(map[string]any)
				assert.Equal(t, expectedSanitized, field["name"])
			},
		},
		{
			name:        "ListProjectItems sanitizes field values",
			toolFactory: ListProjectItems,
			mockPath:    GetOrgsProjectsV2ItemsByProject,
			mockData: []map[string]any{{
				"id": 1001,
				"fields": []map[string]any{{
					"id":    123,
					"name":  "Status",
					"value": maliciousPayload,
				}},
			}},
			requestArgs: map[string]any{
				"owner":          "octo-org",
				"owner_type":     "org",
				"project_number": float64(123),
			},
			validateFunc: func(t *testing.T, responseText string) {
				var resp map[string]any
				err := json.Unmarshal([]byte(responseText), &resp)
				require.NoError(t, err)
				items := resp["items"].([]any)
				item := items[0].(map[string]any)
				fields := item["fields"].([]any)
				field := fields[0].(map[string]any)
				assert.Equal(t, expectedSanitized, field["value"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.mockPath: mockResponse(t, http.StatusOK, tc.mockData),
			})
			client := gh.NewClient(mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			serverTool := tc.toolFactory(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)
			request := createMCPRequest(tc.requestArgs)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			require.False(t, result.IsError)
			tc.validateFunc(t, getTextResult(t, result).Text)
		})
	}
}
