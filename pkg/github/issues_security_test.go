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

func Test_IssuesSecurity(t *testing.T) {
	t.Parallel()

	maliciousDescription := "Label with <script>alert('xss')</script><b>safe</b>"
	expectedDescription := "Label with <b>safe</b>"

	mockIssueLabelsResponse := githubv4mock.DataResponse(map[string]any{
		"repository": map[string]any{
			"issue": map[string]any{
				"labels": map[string]any{
					"nodes": []map[string]any{
						{
							"id":          "label-1",
							"name":        "security-risk",
							"color":       "ff0000",
							"description": maliciousDescription,
						},
					},
					"totalCount": 1,
				},
			},
		},
	})

	t.Run("GetIssueLabels sanitizes description", func(t *testing.T) {
		queryStr := "query($issueNumber:Int!$owner:String!$repo:String!){repository(owner: $owner, name: $repo){issue(number: $issueNumber){labels(first: 100){nodes{id,name,color,description},totalCount}}}}"
		vars := map[string]interface{}{
			"owner":       "test-owner",
			"repo":        "test-repo",
			"issueNumber": 1,
		}
		matcher := githubv4mock.NewQueryMatcher(queryStr, vars, mockIssueLabelsResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)

		result, err := GetIssueLabels(context.Background(), gqlClient, "test-owner", "test-repo", 1)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		labels := response["labels"].([]any)
		assert.Len(t, labels, 1)
		label := labels[0].(map[string]any)
		assert.Equal(t, expectedDescription, label["description"])
	})

	t.Run("fragmentToIssue sanitizes label description", func(t *testing.T) {
		fragment := IssueFragment{
			Number: 1,
			Title:  "Issue Title",
			Body:   "Issue Body",
			State:  "OPEN",
			Labels: struct {
				Nodes []struct {
					Name        githubv4.String
					ID          githubv4.String
					Description githubv4.String
				}
			}{
				Nodes: []struct {
					Name        githubv4.String
					ID          githubv4.String
					Description githubv4.String
				}{
					{
						Name:        "security-risk",
						ID:          "label-1",
						Description: githubv4.String(maliciousDescription),
					},
				},
			},
		}

		issue := fragmentToIssue(fragment)
		require.Len(t, issue.Labels, 1)
		assert.Equal(t, expectedDescription, *issue.Labels[0].Description)
	})
}
