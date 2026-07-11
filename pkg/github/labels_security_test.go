package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsXSS(t *testing.T) {
	maliciousDescription := "Something isn't working <script>alert('xss')</script>"
	sanitizedDescription := "Something isn&#39;t working "

	tests := []struct {
		name       string
		toolGetter func(translations.TranslationHelperFunc) inventory.ServerTool
		args       map[string]any
		mockData   map[string]any
		query      any
		vars       map[string]any
	}{
		{
			name:       "GetLabel sanitizes description",
			toolGetter: GetLabel,
			args: map[string]any{
				"owner": "owner",
				"repo":  "repo",
				"name":  "bug",
			},
			query: struct {
				Repository struct {
					Label struct {
						ID          githubv4.ID
						Name        githubv4.String
						Color       githubv4.String
						Description githubv4.String
					} `graphql:"label(name: $name)"`
				} `graphql:"repository(owner: $owner, name: $repo)"`
			}{},
			vars: map[string]any{
				"owner": githubv4.String("owner"),
				"repo":  githubv4.String("repo"),
				"name":  githubv4.String("bug"),
			},
			mockData: map[string]any{
				"repository": map[string]any{
					"label": map[string]any{
						"id":          githubv4.ID("test-label-id"),
						"name":        githubv4.String("bug"),
						"color":       githubv4.String("d73a4a"),
						"description": githubv4.String(maliciousDescription),
					},
				},
			},
		},
		{
			name:       "ListLabels sanitizes description",
			toolGetter: ListLabels,
			args: map[string]any{
				"owner": "owner",
				"repo":  "repo",
			},
			query: struct {
				Repository struct {
					Labels struct {
						Nodes []struct {
							ID          githubv4.ID
							Name        githubv4.String
							Color       githubv4.String
							Description githubv4.String
						}
						TotalCount githubv4.Int
					} `graphql:"labels(first: 100)"`
				} `graphql:"repository(owner: $owner, name: $repo)"`
			}{},
			vars: map[string]any{
				"owner": githubv4.String("owner"),
				"repo":  githubv4.String("repo"),
			},
			mockData: map[string]any{
				"repository": map[string]any{
					"labels": map[string]any{
						"nodes": []any{
							map[string]any{
								"id":          githubv4.ID("label-1"),
								"name":        githubv4.String("bug"),
								"color":       githubv4.String("d73a4a"),
								"description": githubv4.String(maliciousDescription),
							},
						},
						"totalCount": githubv4.Int(1),
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := githubv4mock.NewMockedHTTPClient(
				githubv4mock.NewQueryMatcher(tc.query, tc.vars, githubv4mock.DataResponse(tc.mockData)),
			)
			client := githubv4.NewClient(mockedClient)
			deps := BaseDeps{
				GQLClient: client,
			}
			serverTool := tc.toolGetter(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)

			request := createMCPRequest(tc.args)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			assert.False(t, result.IsError)

			textContent := getTextResult(t, result)

			if tc.name == "ListLabels sanitizes description" {
				var response struct {
					Labels []struct {
						Description string `json:"description"`
					} `json:"labels"`
				}
				err = json.Unmarshal([]byte(textContent.Text), &response)
				require.NoError(t, err)
				assert.Equal(t, sanitizedDescription, response.Labels[0].Description)
			} else {
				var response struct {
					Description string `json:"description"`
				}
				err = json.Unmarshal([]byte(textContent.Text), &response)
				require.NoError(t, err)
				assert.Equal(t, sanitizedDescription, response.Description)
			}
		})
	}
}
