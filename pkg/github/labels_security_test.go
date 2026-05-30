// pkg/github/labels_security_test.go
// Note: This test file resides in the github package and relies on package-level
// helper functions defined in helper_test.go (e.g., createMCPRequest, getTextResult).
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

func TestLabelsSanitization(t *testing.T) {
	t.Parallel()

	maliciousName := "bug <script>alert('xss-name')</script>"
	maliciousDescription := "Something isn't working <img src=x onerror=alert('xss-desc')>"

	// Expected sanitized values based on bluemonday.StrictPolicy plus allowed tags
	// <script> will be stripped.
	// <img> is allowed, but onerror attribute is NOT allowed.
	// Note: bluemonday escapes single quotes to &#39;

	expectedSanitizedName := "bug "
	expectedSanitizedDescription := "Something isn&#39;t working <img src=\"x\">"

	t.Run("GetLabel sanitizes name and description", func(t *testing.T) {
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
							"name":        githubv4.String(maliciousName),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String(maliciousDescription),
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

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  "bug",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		assert.Equal(t, expectedSanitizedName, label["name"])
		assert.Equal(t, expectedSanitizedDescription, label["description"])
	})

	t.Run("ListLabels sanitizes name and description", func(t *testing.T) {
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
									"name":        githubv4.String(maliciousName),
									"color":       githubv4.String("d73a4a"),
									"description": githubv4.String(maliciousDescription),
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

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		labels := response["labels"].([]any)
		require.Len(t, labels, 1)
		label := labels[0].(map[string]any)

		assert.Equal(t, expectedSanitizedName, label["name"])
		assert.Equal(t, expectedSanitizedDescription, label["description"])
	})
}
