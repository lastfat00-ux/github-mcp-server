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

	xssPayload := "<script>alert('xss')</script><b>bug</b>"
	expectedSanitized := "<b>bug</b>"

	t.Run("GetLabel sanitizes XSS in label description", func(t *testing.T) {
		mockClient := githubv4mock.NewMockedHTTPClient(
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
							"id":          githubv4.ID("test-id"),
							"name":        githubv4.String("bug"),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String(xssPayload),
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockClient)
		deps := BaseDeps{GQLClient: gqlClient}
		tool := GetLabel(translations.NullTranslationHelper)
		handler := tool.Handler(deps)

		req := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		})

		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, res.IsError)

		var resData map[string]any
		textContent := getTextResult(t, res)
		err = json.Unmarshal([]byte(textContent.Text), &resData)
		require.NoError(t, err)

		assert.Equal(t, "bug", resData["name"])
		assert.Equal(t, expectedSanitized, resData["description"])
	})

	t.Run("ListLabels sanitizes XSS in label description", func(t *testing.T) {
		mockClient := githubv4mock.NewMockedHTTPClient(
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
									"description": githubv4.String(xssPayload),
								},
							},
							"totalCount": githubv4.Int(1),
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockClient)
		deps := BaseDeps{GQLClient: gqlClient}
		tool := ListLabels(translations.NullTranslationHelper)
		handler := tool.Handler(deps)

		req := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})

		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, res.IsError)

		var resData struct {
			Labels []map[string]any `json:"labels"`
		}
		textContent := getTextResult(t, res)
		err = json.Unmarshal([]byte(textContent.Text), &resData)
		require.NoError(t, err)
		require.Len(t, resData.Labels, 1)

		assert.Equal(t, "bug", resData.Labels[0]["name"])
		assert.Equal(t, expectedSanitized, resData.Labels[0]["description"])
	})

	t.Run("GetIssueLabels sanitizes XSS in issue label descriptions", func(t *testing.T) {
		mockClient := githubv4mock.NewMockedHTTPClient(
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
										"description": githubv4.String(xssPayload),
									},
								},
								"totalCount": githubv4.Int(1),
							},
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockClient)
		res, err := GetIssueLabels(context.Background(), gqlClient, "owner", "repo", 1)
		require.NoError(t, err)
		require.False(t, res.IsError)

		var resData struct {
			Labels []map[string]any `json:"labels"`
		}
		textContent := getTextResult(t, res)
		err = json.Unmarshal([]byte(textContent.Text), &resData)
		require.NoError(t, err)
		require.Len(t, resData.Labels, 1)

		assert.Equal(t, "bug", resData.Labels[0]["name"])
		assert.Equal(t, expectedSanitized, resData.Labels[0]["description"])
	})
}
