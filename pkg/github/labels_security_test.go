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

	t.Run("GetLabel sanitizes XSS payload in description", func(t *testing.T) {
		t.Parallel()

		serverTool := GetLabel(translations.NullTranslationHelper)

		requestArgs := map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "security-test",
		}

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
					"name":  githubv4.String("security-test"),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"label": map[string]any{
							"id":          githubv4.ID("label-id"),
							"name":        githubv4.String("security-test"),
							"color":       githubv4.String("ff0000"),
							"description": githubv4.String("<b>Safe Bold</b> <script>alert('xss')</script> <img src=x onerror=alert(1)>"),
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

		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		desc, ok := label["description"].(string)
		require.True(t, ok)
		assert.NotContains(t, desc, "<script>")
		assert.NotContains(t, desc, "onerror")
		assert.Contains(t, desc, "<b>Safe Bold</b>")
	})

	t.Run("ListLabels sanitizes XSS payload in description", func(t *testing.T) {
		t.Parallel()

		serverTool := ListLabels(translations.NullTranslationHelper)

		requestArgs := map[string]any{
			"owner": "owner",
			"repo":  "repo",
		}

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
									"description": githubv4.String("<b>Important</b> <script>alert('xss')</script>"),
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

		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)
		require.Len(t, response.Labels, 1)

		desc, ok := response.Labels[0]["description"].(string)
		require.True(t, ok)
		assert.NotContains(t, desc, "<script>")
		assert.Contains(t, desc, "<b>Important</b>")
	})
}
