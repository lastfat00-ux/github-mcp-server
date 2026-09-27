package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	gogh "github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullRequestSecurity_ReviewCommentsXSS(t *testing.T) {
	t.Parallel()

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
												"id":        "PRRC_1",
												"body":      "<b>Safe</b> <script>alert('xss')</script><img src=x onerror=alert('xss')>",
												"path":      "main.go",
												"line":      10,
												"author":    map[string]any{"login": "attacker"},
												"createdAt": "2024-01-01T12:00:00Z",
												"updatedAt": "2024-01-01T12:00:00Z",
												"url":       "https://github.com/owner/repo/pull/42#discussion_r1",
											},
										},
									},
								},
							},
							"pageInfo": map[string]any{
								"hasNextPage":     false,
								"hasPreviousPage": false,
								"startCursor":     "c1",
								"endCursor":       "c2",
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
		Client:          gogh.NewClient(nil),
		GQLClient:       gqlClient,
		RepoAccessCache: stubRepoAccessCache(gqlClient, 5*time.Minute),
		Flags:           stubFeatureFlags(map[string]bool{"lockdown-mode": false}),
		T:               translations.NullTranslationHelper,
	}

	serverTool := PullRequestRead(translations.NullTranslationHelper)
	handler := serverTool.Handler(deps)

	req := createMCPRequest(map[string]interface{}{
		"method":     "get_review_comments",
		"owner":      "owner",
		"repo":       "repo",
		"pullNumber": float64(42),
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &req)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	assert.NotContains(t, textContent.Text, "<script>")
	assert.NotContains(t, textContent.Text, "onerror")
	assert.Contains(t, textContent.Text, "Safe")
}

func TestPullRequestSecurity_ReviewsXSS(t *testing.T) {
	t.Parallel()

	mockReviews := []*gogh.PullRequestReview{
		{
			ID:    gogh.Ptr(int64(101)),
			State: gogh.Ptr("COMMENTED"),
			Body:  gogh.Ptr("<b>Valid Review</b> <script>alert('xss')</script>"),
			User:  &gogh.User{Login: gogh.Ptr("reviewer")},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposPullsReviewsByOwnerByRepoByPullNumber: mockResponse(t, http.StatusOK, mockReviews),
	})

	client := gogh.NewClient(mockedClient)
	deps := BaseDeps{
		Client:          client,
		RepoAccessCache: stubRepoAccessCache(githubv4.NewClient(nil), 5*time.Minute),
		Flags:           stubFeatureFlags(map[string]bool{"lockdown-mode": false}),
		T:               translations.NullTranslationHelper,
	}

	serverTool := PullRequestRead(translations.NullTranslationHelper)
	handler := serverTool.Handler(deps)

	req := createMCPRequest(map[string]interface{}{
		"method":     "get_reviews",
		"owner":      "owner",
		"repo":       "repo",
		"pullNumber": float64(42),
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &req)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)

	var returnedReviews []*gogh.PullRequestReview
	err = json.Unmarshal([]byte(textContent.Text), &returnedReviews)
	require.NoError(t, err)
	require.Len(t, returnedReviews, 1)

	body := returnedReviews[0].GetBody()
	assert.NotContains(t, body, "<script>")
	assert.Contains(t, body, "Valid Review")
}
