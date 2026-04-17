package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPullRequestReviews_Sanitization(t *testing.T) {
	// Setup mock review with malicious content
	maliciousBody := "Review with <script>alert('xss')</script> and <b>bold</b> text."
	expectedBody := "Review with  and <b>bold</b> text."

	mockReviews := []*github.PullRequestReview{
		{
			ID:    github.Ptr(int64(123)),
			Body:  github.Ptr(maliciousBody),
			State: github.Ptr("APPROVED"),
			User: &github.User{
				Login: github.Ptr("attacker"),
			},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposPullsReviewsByOwnerByRepoByPullNumber: mockResponse(t, http.StatusOK, mockReviews),
	})

	client := github.NewClient(mockedClient)

	// Call GetPullRequestReviews directly
	result, err := GetPullRequestReviews(context.Background(), client, nil, "owner", "repo", 42, FeatureFlags{})
	require.NoError(t, err)

	textContent := getTextResult(t, result)
	var reviews []*github.PullRequestReview
	err = json.Unmarshal([]byte(textContent.Text), &reviews)
	require.NoError(t, err)

	require.Len(t, reviews, 1)
	assert.Equal(t, expectedBody, *reviews[0].Body)
}
