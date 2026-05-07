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

func Test_IssuesXSSSanitization(t *testing.T) {
	maliciousBody := "Malicious <script>alert('xss')</script> comment"
	expectedSanitizedBody := "Malicious  comment"

	mockComment := &github.IssueComment{
		ID:   github.Ptr(int64(123)),
		Body: github.Ptr(maliciousBody),
	}

	t.Run("GetIssueComments sanitizes comment bodies", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, []*github.IssueComment{mockComment}),
		})

		client := github.NewClient(mockedClient)

		result, err := GetIssueComments(context.Background(), client, nil, "owner", "repo", 1, PaginationParams{}, FeatureFlags{})

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var comments []*github.IssueComment
		err = json.Unmarshal([]byte(textContent.Text), &comments)
		require.NoError(t, err)
		require.Len(t, comments, 1)
		assert.Equal(t, expectedSanitizedBody, *comments[0].Body)
	})
}
