package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuesSecurity(t *testing.T) {
	t.Run("GetIssueLabels description sanitization", func(t *testing.T) {
		qGetIssueLabels := struct {
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
		}{}

		vars := map[string]any{
			"owner":       githubv4.String("owner"),
			"repo":        githubv4.String("repo"),
			"issueNumber": githubv4.Int(1),
		}

		maliciousResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{
				"issue": map[string]any{
					"labels": map[string]any{
						"nodes": []any{
							map[string]any{
								"id":          githubv4.ID("label-1"),
								"name":        githubv4.String("bug"),
								"color":       githubv4.String("d73a4a"),
								"description": githubv4.String("Malicious <script>alert('xss')</script> Description"),
							},
						},
						"totalCount": githubv4.Int(1),
					},
				},
			},
		})

		matcher := githubv4mock.NewQueryMatcher(qGetIssueLabels, vars, maliciousResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)

		res, err := GetIssueLabels(context.Background(), gqlClient, "owner", "repo", 1)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var response struct {
			Labels []map[string]any `json:"labels"`
		}
		require.NoError(t, json.Unmarshal([]byte(text), &response))

		assert.Len(t, response.Labels, 1)
		assert.Equal(t, "Malicious  Description", response.Labels[0]["description"])
	})
}
