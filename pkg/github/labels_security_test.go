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

	// Malicious payload with invisible zero-width space (\u200B), BiDi override (\u202A), and plain-text angle brackets (<Component>)
	payloadWithInvisibleChars := "Bug in \u200B<Component> \u202Awith BiDi"
	expectedSanitized := "Bug in <Component> with BiDi"

	t.Run("GetLabel sanitizes invisible characters while preserving angle brackets", func(t *testing.T) {
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
							"description": githubv4.String(payloadWithInvisibleChars),
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

		var output map[string]any
		text := getTextResult(t, result)
		err = json.Unmarshal([]byte(text.Text), &output)
		require.NoError(t, err)

		assert.Equal(t, "bug", output["name"])
		assert.Equal(t, expectedSanitized, output["description"])
	})

	t.Run("ListLabels sanitizes invisible characters while preserving angle brackets", func(t *testing.T) {
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
									"description": githubv4.String(payloadWithInvisibleChars),
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

		var output map[string]any
		text := getTextResult(t, result)
		err = json.Unmarshal([]byte(text.Text), &output)
		require.NoError(t, err)

		labels, ok := output["labels"].([]any)
		require.True(t, ok)
		require.Len(t, labels, 1)

		firstLabel := labels[0].(map[string]any)
		assert.Equal(t, expectedSanitized, firstLabel["description"])
	})

	t.Run("GetIssueLabels sanitizes invisible characters while preserving angle brackets", func(t *testing.T) {
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
										"description": githubv4.String(payloadWithInvisibleChars),
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
		assert.False(t, result.IsError)

		var output map[string]any
		text := getTextResult(t, result)
		err = json.Unmarshal([]byte(text.Text), &output)
		require.NoError(t, err)

		labels, ok := output["labels"].([]any)
		require.True(t, ok)
		require.Len(t, labels, 1)

		firstLabel := labels[0].(map[string]any)
		assert.Equal(t, expectedSanitized, firstLabel["description"])
	})
}
