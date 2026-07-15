package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	gogh "github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CommentsXSS(t *testing.T) {
	maliciousPayload := "Hello<script>alert('xss')</script>world"
	expectedSanitized := "Helloworld"

	t.Run("GetIssueComments sanitization", func(t *testing.T) {
		mockComments := []*gogh.IssueComment{
			{
				ID:   gogh.Ptr(int64(1)),
				Body: gogh.Ptr(maliciousPayload),
				User: &gogh.User{Login: gogh.Ptr("attacker")},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, mockComments),
		})

		client := gogh.NewClient(mockedClient)

		result, err := GetIssueComments(context.Background(), client, nil, "owner", "repo", 1, PaginationParams{}, FeatureFlags{})
		require.NoError(t, err)
		require.NotNil(t, result)

		text := getTextResult(t, result).Text

		var returnedComments []*gogh.IssueComment
		err = json.Unmarshal([]byte(text), &returnedComments)
		require.NoError(t, err)

		assert.Equal(t, expectedSanitized, *returnedComments[0].Body)
	})
}
