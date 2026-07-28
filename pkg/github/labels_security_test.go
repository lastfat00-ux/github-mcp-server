package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsXSS(t *testing.T) {
	t.Run("GetLabel sanitization", func(t *testing.T) {
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
							"id":          githubv4.ID("test-label-id"),
							"name":        githubv4.String("bug"),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String("Something is <script>alert('XSS')</script>broken"),
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: client,
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &label))

		assert.Equal(t, "Something is broken", label["description"])
	})

	t.Run("ListLabels sanitization", func(t *testing.T) {
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
									"description": githubv4.String("Something is <script>alert('XSS')</script>broken"),
								},
							},
							"totalCount": githubv4.Int(1),
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: client,
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]any{
			"owner": "owner",
			"repo":  "repo",
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &response))
		require.Len(t, response.Labels, 1)

		assert.Equal(t, "Something is broken", response.Labels[0]["description"])
	})

	t.Run("GetIssueLabels sanitization", func(t *testing.T) {
		mockedClient := githubv4mock.NewMockedHTTPClient(
			githubv4mock.NewQueryMatcher(
				struct {
					Repository struct {
						Issue struct {
							Labels struct {
								Nodes []struct {
									ID          githubv4.ID
									Name        githubv4.String
									Color       githubv4.String
									Description githubv4.String
								}
								TotalCount githubv4.Int
							} `graphql:"labels(first: 100)"`
						} `graphql:"issue(number: $issueNumber)"`
					} `graphql:"repository(owner: $owner, name: $repo)"`
				}{},
				map[string]any{
					"owner":       githubv4.String("owner"),
					"repo":        githubv4.String("repo"),
					"issueNumber": githubv4.Int(1),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"issue": map[string]any{
							"labels": map[string]any{
								"nodes": []any{
									map[string]any{
										"id":          githubv4.ID("label-1"),
										"name":        githubv4.String("bug"),
										"color":       githubv4.String("d73a4a"),
										"description": githubv4.String("Something is <script>alert('XSS')</script>broken"),
									},
								},
								"totalCount": githubv4.Int(1),
							},
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		result, err := GetIssueLabels(context.Background(), client, "owner", "repo", 1)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &response))
		require.Len(t, response.Labels, 1)

		assert.Equal(t, "Something is broken", response.Labels[0]["description"])
	})
}
