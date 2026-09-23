package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsXSS(t *testing.T) {
	t.Parallel()

	t.Run("GetLabel sanitizes malicious description", func(t *testing.T) {
		serverTool := GetLabel(translations.NullTranslationHelper)

		mockedClient := githubv4mock.NewMockedHTTPClient(
			githubv4mock.NewQueryMatcher(
				struct {
					Repository struct {
						Label struct {
							ID          githubv4.ID
							Name        githubv4.String
							Color       githubv4.String
							Description githubv4.String
						} `graphql:"label(name: $name)"`
					} `graphql:"repository(owner: $owner, name: $repo)"`
				}{},
				map[string]any{
					"owner": githubv4.String("owner"),
					"repo":  githubv4.String("repo"),
					"name":  githubv4.String("bug"),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"label": map[string]any{
							"id":          githubv4.ID("label-id"),
							"name":        githubv4.String("bug"),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String("Something <b>is</b> broken <script>alert('xss')</script>"),
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{GQLClient: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		text := getTextResult(t, result).Text
		var label map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &label))

		assert.Equal(t, "Something <b>is</b> broken ", label["description"])
	})

	t.Run("ListLabels sanitizes malicious description", func(t *testing.T) {
		serverTool := ListLabels(translations.NullTranslationHelper)

		mockedClient := githubv4mock.NewMockedHTTPClient(
			githubv4mock.NewQueryMatcher(
				struct {
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
				map[string]any{
					"owner": githubv4.String("owner"),
					"repo":  githubv4.String("repo"),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"labels": map[string]any{
							"nodes": []any{
								map[string]any{
									"id":          githubv4.ID("label-1"),
									"name":        githubv4.String("bug"),
									"color":       githubv4.String("d73a4a"),
									"description": githubv4.String("Malicious <script>alert(1)</script> description"),
								},
							},
							"totalCount": githubv4.Int(1),
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{GQLClient: client}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		text := getTextResult(t, result).Text
		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		require.NoError(t, json.Unmarshal([]byte(text), &response))

		require.Len(t, response.Labels, 1)
		assert.Equal(t, "Malicious  description", response.Labels[0]["description"])
	})
}
