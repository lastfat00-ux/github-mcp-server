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

	t.Run("GetLabel description is sanitized", func(t *testing.T) {
		serverTool := GetLabel(translations.NullTranslationHelper)

		vars := map[string]interface{}{
			"owner": githubv4.String("owner"),
			"repo":  githubv4.String("repo"),
			"name":  githubv4.String("bug"),
		}

		maliciousResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{
				"label": map[string]any{
					"id":          githubv4.ID("test-label-id"),
					"name":        githubv4.String("bug"),
					"color":       githubv4.String("d73a4a"),
					"description": githubv4.String("Malicious <script>alert('xss')</script> description"),
				},
			},
		})

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
				vars,
				maliciousResponse,
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: client,
		}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		assert.Equal(t, "Malicious  description", label["description"])
	})

	t.Run("ListLabels descriptions are sanitized", func(t *testing.T) {
		serverTool := ListLabels(translations.NullTranslationHelper)

		vars := map[string]interface{}{
			"owner": githubv4.String("owner"),
			"repo":  githubv4.String("repo"),
		}

		maliciousResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{
				"labels": map[string]any{
					"nodes": []any{
						map[string]any{
							"id":          githubv4.ID("label-1"),
							"name":        githubv4.String("bug"),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String("Malicious <script>alert('xss')</script> description 1"),
						},
						map[string]any{
							"id":          githubv4.ID("label-2"),
							"name":        githubv4.String("enhancement"),
							"color":       githubv4.String("a2eeef"),
							"description": githubv4.String("Malicious <iframe src='javascript:alert(1)'></iframe> description 2"),
						},
					},
					"totalCount": githubv4.Int(2),
				},
			},
		})

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
				vars,
				maliciousResponse,
			),
		)

		client := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: client,
		}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})
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

		require.Len(t, response.Labels, 2)
		assert.Equal(t, "Malicious  description 1", response.Labels[0]["description"])
		assert.Equal(t, "Malicious  description 2", response.Labels[1]["description"])
	})
}
