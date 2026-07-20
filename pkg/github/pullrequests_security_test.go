package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullRequestSecurity_ReviewCommentsXSS(t *testing.T) {
	serverTool := PullRequestRead(translations.NullTranslationHelper)

	// Setup GraphQL client with mock review threads containing XSS payloads
	gqlHTTPClient := githubv4mock.NewMockedHTTPClient(
		githubv4mock.NewQueryMatcher(
			reviewThreadsQuery{},
			map[string]interface{}{
				"owner":             githubv4.String("owner"),
				"repo":              githubv4.String("repo"),
				"prNum":             githubv4.Int(42),
				"first":             githubv4.Int(30),
				"commentsPerThread": githubv4.Int(100),
				"after":             (*githubv4.String)(nil),
			},
			githubv4mock.DataResponse(map[string]any{
				"repository": map[string]any{
					"pullRequest": map[string]any{
						"reviewThreads": map[string]any{
							"nodes": []map[string]any{
								{
									"id":          "RT_1",
									"isResolved":  false,
									"isOutdated":  false,
									"isCollapsed": false,
									"comments": map[string]any{
										"totalCount": 1,
										"nodes": []map[string]any{
											{
												"id":   "COMMENT_1",
												"body": "Malicious comment <script>alert('xss')</script><img src=x onerror=alert(1)>",
												"path": "file1.go",
												"line": 5,
												"author": map[string]any{
													"login": "attacker",
												},
												"createdAt": "2024-01-01T12:00:00Z",
												"updatedAt": "2024-01-01T12:00:00Z",
												"url":       "https://github.com/owner/repo/pull/42#discussion_r101",
											},
										},
									},
								},
							},
							"pageInfo": map[string]any{
								"hasNextPage":     false,
								"hasPreviousPage": false,
								"startCursor":     "cursor1",
								"endCursor":       "cursor2",
							},
							"totalCount": 1,
						},
					},
				},
			}),
		),
	)

	gqlClient := githubv4.NewClient(gqlHTTPClient)
	deps := BaseDeps{
		Client:          github.NewClient(nil),
		GQLClient:       gqlClient,
		RepoAccessCache: stubRepoAccessCache(gqlClient, 5*time.Minute),
		Flags:           stubFeatureFlags(map[string]bool{"lockdown-mode": false}),
	}
	handler := serverTool.Handler(deps)

	requestArgs := map[string]interface{}{
		"method":     "get_review_comments",
		"owner":      "owner",
		"repo":       "repo",
		"pullNumber": float64(42),
	}
	request := createMCPRequest(requestArgs)

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var response map[string]interface{}
	err = json.Unmarshal([]byte(textContent.Text), &response)
	require.NoError(t, err)

	// Validate review threads comments are sanitized
	threads := response["reviewThreads"].([]interface{})
	assert.Len(t, threads, 1)

	thread := threads[0].(map[string]interface{})
	comments := thread["Comments"].(map[string]interface{})
	commentNodes := comments["Nodes"].([]interface{})
	assert.Len(t, commentNodes, 1)

	comment1 := commentNodes[0].(map[string]interface{})
	// <script> should be stripped completely and onerror should be stripped from img
	assert.Equal(t, `Malicious comment <img src="x">`, comment1["Body"])
}

func TestPullRequestSecurity_ReviewsXSS(t *testing.T) {
	serverTool := PullRequestRead(translations.NullTranslationHelper)

	// Mock REST response containing PR reviews with XSS payloads
	mockReviews := []*github.PullRequestReview{
		{
			ID:    github.Ptr(int64(201)),
			State: github.Ptr("APPROVED"),
			Body:  github.Ptr("Malicious review <script>alert(2)</script><img src=y onerror=alert(3)>"),
			User: &github.User{
				Login: github.Ptr("attacker"),
			},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposPullsReviewsByOwnerByRepoByPullNumber: mockResponse(t, http.StatusOK, mockReviews),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client:          client,
		GQLClient:       githubv4.NewClient(nil),
		RepoAccessCache: stubRepoAccessCache(githubv4.NewClient(nil), 5*time.Minute),
		Flags:           stubFeatureFlags(map[string]bool{"lockdown-mode": false}),
	}
	handler := serverTool.Handler(deps)

	requestArgs := map[string]interface{}{
		"method":     "get_reviews",
		"owner":      "owner",
		"repo":       "repo",
		"pullNumber": float64(42),
	}
	request := createMCPRequest(requestArgs)

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var response []map[string]interface{}
	err = json.Unmarshal([]byte(textContent.Text), &response)
	require.NoError(t, err)

	assert.Len(t, response, 1)
	review := response[0]
	// Body should be sanitized correctly
	assert.Equal(t, `Malicious review <img src="y">`, review["body"])
}
