package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurity_GapsSanitization(t *testing.T) {
	t.Parallel()

	maliciousPayload := "malicious<script>alert('xss')</script>content"
	sanitizedPayload := "maliciouscontent"

	t.Run("GetIssueComments sanitizes body", func(t *testing.T) {
		mockComments := []*github.IssueComment{
			{
				ID:   github.Ptr(int64(123)),
				Body: github.Ptr(maliciousPayload),
				User: &github.User{Login: github.Ptr("user1")},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposIssuesCommentsByOwnerByRepoByIssueNumber: mockResponse(t, http.StatusOK, mockComments),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		serverTool := IssueRead(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"method":       "get_comments",
			"owner":        "owner",
			"repo":         "repo",
			"issue_number": float64(42),
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)
		var returnedComments []*github.IssueComment
		err = json.Unmarshal([]byte(textContent.Text), &returnedComments)
		require.NoError(t, err)

		require.Len(t, returnedComments, 1)
		assert.Equal(t, sanitizedPayload, *returnedComments[0].Body)
	})

	t.Run("ListNotifications sanitizes Subject.Title", func(t *testing.T) {
		mockNotifications := []*github.Notification{
			{
				ID: github.Ptr("1"),
				Subject: &github.NotificationSubject{
					Title: github.Ptr(maliciousPayload),
				},
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotifications: mockResponse(t, http.StatusOK, mockNotifications),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		serverTool := ListNotifications(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)
		var returnedNotifications []*github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &returnedNotifications)
		require.NoError(t, err)

		require.Len(t, returnedNotifications, 1)
		assert.Equal(t, sanitizedPayload, *returnedNotifications[0].Subject.Title)
	})

	t.Run("GetGlobalSecurityAdvisory sanitizes Summary and Description", func(t *testing.T) {
		mockAdvisory := &github.GlobalSecurityAdvisory{
			SecurityAdvisory: github.SecurityAdvisory{
				Summary:     github.Ptr(maliciousPayload),
				Description: github.Ptr(maliciousPayload),
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetAdvisoriesByGhsaID: mockResponse(t, http.StatusOK, mockAdvisory),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		serverTool := GetGlobalSecurityAdvisory(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"ghsaId": "GHSA-xxxx-xxxx-xxxx",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		textContent := getTextResult(t, result)
		var returnedAdvisory github.GlobalSecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &returnedAdvisory)
		require.NoError(t, err)

		assert.Equal(t, sanitizedPayload, *returnedAdvisory.Summary)
		assert.Equal(t, sanitizedPayload, *returnedAdvisory.Description)
	})
}
