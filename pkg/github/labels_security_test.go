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

func TestLabels_SecuritySanitization(t *testing.T) {
	t.Parallel()

	maliciousName := "malicious<script>alert('xss')</script>label"
	maliciousDesc := "malicious<img src=x onerror=alert('xss')>description"
	// Label names in data objects are NOT sanitized to preserve data integrity for identifiers
	unsanitizedName := maliciousName
	sanitizedName := "maliciouslabel"
	// bluemonday's policy used in pkg/sanitize allows <img> tags but strips onerror
	sanitizedDesc := "malicious<img src=\"x\">description"

	t.Run("GetLabel sanitizes description but not name in data object", func(t *testing.T) {
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
					"name":  githubv4.String(maliciousName),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"label": map[string]any{
							"id":          githubv4.ID("test-label-id"),
							"name":        githubv4.String(maliciousName),
							"color":       githubv4.String("d73a4a"),
							"description": githubv4.String(maliciousDesc),
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: gqlClient,
		}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
			"name":  maliciousName,
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		assert.Equal(t, unsanitizedName, label["name"])
		assert.Equal(t, sanitizedDesc, label["description"])
	})

	t.Run("ListLabels sanitizes description but not name in data object", func(t *testing.T) {
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
									"description": githubv4.String(maliciousDesc),
								},
							},
							"totalCount": githubv4.Int(1),
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: gqlClient,
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
		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		require.Len(t, response.Labels, 1)
		assert.Equal(t, unsanitizedName, response.Labels[0]["name"])
		assert.Equal(t, sanitizedDesc, response.Labels[0]["description"])
	})

	t.Run("LabelWrite sanitizes success message", func(t *testing.T) {
		serverTool := LabelWrite(translations.NullTranslationHelper)

		mockedClient := githubv4mock.NewMockedHTTPClient(
			githubv4mock.NewQueryMatcher(
				struct {
					Repository struct {
						ID githubv4.ID
					} `graphql:"repository(owner: $owner, name: $repo)"`
				}{},
				map[string]any{
					"owner": githubv4.String("owner"),
					"repo":  githubv4.String("repo"),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"id": githubv4.ID("test-repo-id"),
					},
				}),
			),
			githubv4mock.NewMutationMatcher(
				struct {
					CreateLabel struct {
						Label struct {
							Name githubv4.String
							ID   githubv4.ID
						}
					} `graphql:"createLabel(input: $input)"`
				}{},
				githubv4.CreateLabelInput{
					RepositoryID: githubv4.ID("test-repo-id"),
					Name:         githubv4.String(maliciousName),
					Color:        githubv4.String("f29513"),
				},
				nil,
				githubv4mock.DataResponse(map[string]any{
					"createLabel": map[string]any{
						"label": map[string]any{
							"id":   githubv4.ID("new-label-id"),
							"name": githubv4.String(maliciousName),
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockedClient)
		deps := BaseDeps{
			GQLClient: gqlClient,
		}
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"method": "create",
			"owner":  "owner",
			"repo":   "repo",
			"name":   maliciousName,
			"color":  "f29513",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		assert.Contains(t, textContent.Text, sanitizedName)
		assert.NotContains(t, textContent.Text, "<script>")
	})
}
