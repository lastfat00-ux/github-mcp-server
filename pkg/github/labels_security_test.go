package github

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsXSS(t *testing.T) {
	t.Parallel()

	maliciousPayload := "Something is <script>alert('XSS')</script> broken!"
	expectedSanitized := "Something is  broken!"

	// 1. Test GetLabel XSS Sanitization
	t.Run("GetLabel_XSS", func(t *testing.T) {
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
							"description": githubv4.String(maliciousPayload),
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
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		assert.Equal(t, expectedSanitized, label["description"])
	})

	// 2. Test ListLabels XSS Sanitization
	t.Run("ListLabels_XSS", func(t *testing.T) {
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
									"description": githubv4.String(maliciousPayload),
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
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		labels, ok := response["labels"].([]any)
		require.True(t, ok)
		require.Len(t, labels, 1)

		labelMap, ok := labels[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, expectedSanitized, labelMap["description"])
	})

	// 3. Test GetIssueLabels XSS Sanitization
	t.Run("GetIssueLabels_XSS", func(t *testing.T) {
		serverTool := IssueRead(translations.NullTranslationHelper)
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
					"issueNumber": githubv4.Int(123),
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
										"description": githubv4.String(maliciousPayload),
									},
								},
								"totalCount": githubv4.Int(1),
							},
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient:       gqlClient,
			RepoAccessCache: stubRepoAccessCache(gqlClient, 15*time.Minute),
			Flags:           stubFeatureFlags(map[string]bool{"lockdown-mode": false}),
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]any{
			"method":       "get_labels",
			"owner":        "owner",
			"repo":         "repo",
			"issue_number": float64(123),
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		labels, ok := response["labels"].([]any)
		require.True(t, ok)
		require.Len(t, labels, 1)

		labelMap, ok := labels[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, expectedSanitized, labelMap["description"])
	})
}
