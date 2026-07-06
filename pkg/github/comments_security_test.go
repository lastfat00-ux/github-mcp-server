package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommentsXSS(t *testing.T) {
	maliciousPayload := "<b>Safe</b><script>alert('XSS')</script>"
	// Expected sanitized output (bluemonday strips script tags and their content by default)
	expectedSanitized := "<b>Safe</b>"

	t.Run("GetIssueComments sanitization", func(t *testing.T) {
		mockComments := []*github.IssueComment{
			{
				ID:   github.Ptr(int64(1)),
				Body: github.Ptr(maliciousPayload),
				User: &github.User{Login: github.Ptr("attacker")},
			},
		}

		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, mockComments),
		}))

		deps := BaseDeps{Client: client}
		serverTool := IssueRead(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		req := createMCPRequest(map[string]interface{}{
			"method":       "get_comments",
			"owner":        "owner",
			"repo":         "repo",
			"issue_number": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		var returnedComments []*github.IssueComment
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedComments)
		require.NoError(t, err)
		require.Len(t, returnedComments, 1)

		assert.Equal(t, expectedSanitized, *returnedComments[0].Body)
	})

	t.Run("GetSubIssues sanitization", func(t *testing.T) {
		mockSubIssues := []*github.Issue{
			{
				Number: github.Ptr(2),
				Title:  github.Ptr(maliciousPayload),
				Body:   github.Ptr(maliciousPayload),
				User:   &github.User{Login: github.Ptr("attacker")},
			},
		}

		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesSubIssuesByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, mockSubIssues),
		}))

		deps := BaseDeps{Client: client}
		serverTool := IssueRead(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		req := createMCPRequest(map[string]interface{}{
			"method":       "get_sub_issues",
			"owner":        "owner",
			"repo":         "repo",
			"issue_number": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		var returnedSubIssues []*github.Issue
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedSubIssues)
		require.NoError(t, err)
		require.Len(t, returnedSubIssues, 1)

		assert.Equal(t, expectedSanitized, *returnedSubIssues[0].Title)
		assert.Equal(t, expectedSanitized, *returnedSubIssues[0].Body)
	})

	t.Run("GetPullRequestReviewComments sanitization", func(t *testing.T) {
		mockGQLClient := githubv4mock.NewMockedHTTPClient(
			githubv4mock.NewQueryMatcher(
				"query($after:String$commentsPerThread:Int!$first:Int!$owner:String!$prNum:Int!$repo:String!){repository(owner: $owner, name: $repo){pullRequest(number: $prNum){reviewThreads(first: $first, after: $after){nodes{id,isResolved,isOutdated,isCollapsed,comments(first: $commentsPerThread){nodes{id,body,path,line,author{login},createdAt,updatedAt,url},totalCount}},pageInfo{hasNextPage,hasPreviousPage,startCursor,endCursor},totalCount}}}}",
				map[string]any{
					"owner":             githubv4.String("owner"),
					"repo":              githubv4.String("repo"),
					"prNum":             githubv4.Int(1),
					"first":             githubv4.Int(30),
					"commentsPerThread": githubv4.Int(100),
					"after":             (*githubv4.String)(nil),
				},
				githubv4mock.DataResponse(map[string]any{
					"repository": map[string]any{
						"pullRequest": map[string]any{
							"reviewThreads": map[string]any{
								"nodes": []any{
									map[string]any{
										"id":          "thread-1",
										"isResolved":  false,
										"isOutdated":  false,
										"isCollapsed": false,
										"comments": map[string]any{
											"nodes": []any{
												map[string]any{
													"id":   "comment-1",
													"body": githubv4.String(maliciousPayload),
													"path": "file.go",
													"author": map[string]any{
														"login": "attacker",
													},
													"createdAt": "2023-01-01T00:00:00Z",
													"updatedAt": "2023-01-01T00:00:00Z",
													"url":       "https://github.com/owner/repo/pull/1#discussion_r1",
												},
											},
											"totalCount": 1,
										},
									},
								},
								"pageInfo": map[string]any{
									"hasNextPage": false,
								},
								"totalCount": 1,
							},
						},
					},
				}),
			),
		)

		gqlClient := githubv4.NewClient(mockGQLClient)
		client := github.NewClient(nil)
		deps := BaseDeps{Client: client, GQLClient: gqlClient}
		serverTool := PullRequestRead(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		req := createMCPRequest(map[string]interface{}{
			"method":     "get_review_comments",
			"owner":      "owner",
			"repo":       "repo",
			"pullNumber": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		var response struct {
			ReviewThreads []reviewThreadNode `json:"reviewThreads"`
		}
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)
		require.Len(t, response.ReviewThreads, 1)
		require.Len(t, response.ReviewThreads[0].Comments.Nodes, 1)

		assert.Equal(t, expectedSanitized, string(response.ReviewThreads[0].Comments.Nodes[0].Body))
	})

	t.Run("GetPullRequestReviews sanitization", func(t *testing.T) {
		mockReviews := []*github.PullRequestReview{
			{
				ID:   github.Ptr(int64(1)),
				Body: github.Ptr(maliciousPayload),
				User: &github.User{Login: github.Ptr("attacker")},
			},
		}

		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposPullsByOwnerByRepoByPullNumber + "/reviews": mockResponse(t, http.StatusOK, mockReviews),
		}))

		deps := BaseDeps{Client: client}
		serverTool := PullRequestRead(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		req := createMCPRequest(map[string]interface{}{
			"method":     "get_reviews",
			"owner":      "owner",
			"repo":       "repo",
			"pullNumber": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		var returnedReviews []*github.PullRequestReview
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedReviews)
		require.NoError(t, err)
		require.Len(t, returnedReviews, 1)

		assert.Equal(t, expectedSanitized, *returnedReviews[0].Body)
	})
}
