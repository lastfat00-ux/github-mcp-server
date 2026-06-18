package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommentsSanitization(t *testing.T) {
	maliciousBody := "Comment with <script>alert('XSS')</script><b>Safe</b>"
	expectedBody := "Comment with <b>Safe</b>"

	t.Run("Issue Comments Sanitization", func(t *testing.T) {
		mockComments := []*github.IssueComment{
			{
				ID:   github.Ptr(int64(1)),
				Body: github.Ptr(maliciousBody),
				User: &github.User{Login: github.Ptr("attacker")},
			},
		}

		serverTool := IssueRead(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, mockComments),
		})

		deps := BaseDeps{
			Client: github.NewClient(mockedClient),
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]interface{}{
			"method":       "get_comments",
			"owner":        "owner",
			"repo":         "repo",
			"issue_number": float64(42),
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)

		var returnedComments []*github.IssueComment
		err = json.Unmarshal([]byte(textContent.Text), &returnedComments)
		require.NoError(t, err)
		require.Len(t, returnedComments, 1)
		assert.Equal(t, expectedBody, *returnedComments[0].Body)
	})

	t.Run("PR Review Comments Sanitization", func(t *testing.T) {
		// Mock GraphQL response for PR review comments
		mockGQLResponse := map[string]any{
			"data": map[string]any{
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
												"body": maliciousBody,
												"path": "file.txt",
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
								"hasNextPage":     false,
								"hasPreviousPage": false,
								"startCursor":     "cursor-1",
								"endCursor":       "cursor-1",
							},
							"totalCount": 1,
						},
					},
				},
			},
		}

		serverTool := PullRequestRead(translations.NullTranslationHelper)
		mockedGQLClient := MockHTTPClientWithHandler(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockGQLResponse)
		})

		deps := BaseDeps{
			Client:    github.NewClient(nil),
			GQLClient: githubv4.NewClient(mockedGQLClient),
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]interface{}{
			"method":     "get_review_comments",
			"owner":      "owner",
			"repo":       "repo",
			"pullNumber": float64(1),
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)

		var response struct {
			ReviewThreads []reviewThreadNode `json:"reviewThreads"`
		}
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)
		require.Len(t, response.ReviewThreads, 1)
		require.Len(t, response.ReviewThreads[0].Comments.Nodes, 1)
		assert.Equal(t, expectedBody, string(response.ReviewThreads[0].Comments.Nodes[0].Body))
	})

	t.Run("PR Reviews Sanitization", func(t *testing.T) {
		mockReviews := []*github.PullRequestReview{
			{
				ID:   github.Ptr(int64(1)),
				Body: github.Ptr(maliciousBody),
				User: &github.User{Login: github.Ptr("attacker")},
			},
		}

		serverTool := PullRequestRead(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposPullsReviewsByOwnerByRepoByPullNumber: mockResponse(t, http.StatusOK, mockReviews),
		})

		deps := BaseDeps{
			Client: github.NewClient(mockedClient),
		}
		handler := serverTool.Handler(deps)

		requestArgs := map[string]interface{}{
			"method":     "get_reviews",
			"owner":      "owner",
			"repo":       "repo",
			"pullNumber": float64(1),
		}
		request := createMCPRequest(requestArgs)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)

		var returnedReviews []*github.PullRequestReview
		err = json.Unmarshal([]byte(textContent.Text), &returnedReviews)
		require.NoError(t, err)
		require.Len(t, returnedReviews, 1)
		assert.Equal(t, expectedBody, *returnedReviews[0].Body)
	})
}
