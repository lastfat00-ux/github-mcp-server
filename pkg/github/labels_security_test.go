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

	xssDescription := "<script>alert('xss')</script><b>Valid Label Description</b>"
	expectedSanitized := "<b>Valid Label Description</b>"

	t.Run("GetLabel sanitizes XSS in description", func(t *testing.T) {
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
							"description": githubv4.String(xssDescription),
						},
					},
				}),
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{GQLClient: client}
		handler := serverTool.Handler(deps)

		req := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		})
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		assert.False(t, res.IsError)

		textContent := getTextResult(t, res)

		var labelRes map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &labelRes)
		require.NoError(t, err)
		desc, ok := labelRes["description"].(string)
		require.True(t, ok)
		assert.NotContains(t, desc, "<script>")
		assert.NotContains(t, desc, "alert")
		assert.Equal(t, expectedSanitized, desc)
	})

	t.Run("ListLabels sanitizes XSS in description", func(t *testing.T) {
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
									"description": githubv4.String(xssDescription),
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

		req := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		assert.False(t, res.IsError)

		textContent := getTextResult(t, res)

		var listRes struct {
			Labels []map[string]any `json:"labels"`
		}
		err = json.Unmarshal([]byte(textContent.Text), &listRes)
		require.NoError(t, err)
		require.Len(t, listRes.Labels, 1)
		desc, ok := listRes.Labels[0]["description"].(string)
		require.True(t, ok)
		assert.NotContains(t, desc, "<script>")
		assert.NotContains(t, desc, "alert")
		assert.Equal(t, expectedSanitized, desc)
	})
}
