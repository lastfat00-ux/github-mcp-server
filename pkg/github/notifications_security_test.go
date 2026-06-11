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

func Test_NotificationsSanitization(t *testing.T) {
	t.Run("ListNotifications sanitization", func(t *testing.T) {
		maliciousTitle := "Malicious <script>alert('XSS')</script> notification"
		mockNotification := &github.Notification{
			ID: github.Ptr("123"),
			Subject: &github.NotificationSubject{
				Title: github.Ptr(maliciousTitle),
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotifications: mockResponse(t, http.StatusOK, []*github.Notification{mockNotification}),
		})

		serverTool := ListNotifications(translations.NullTranslationHelper)
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		handler := serverTool.Handler(deps)
		request := createMCPRequest(map[string]interface{}{})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned []*github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		require.NoError(t, err)
		require.NotEmpty(t, returned)

		// If sanitized, the <script> tag should be removed
		assert.NotContains(t, *returned[0].Subject.Title, "<script>")
		assert.Equal(t, "Malicious  notification", *returned[0].Subject.Title)
	})

	t.Run("GetNotificationDetails sanitization", func(t *testing.T) {
		maliciousTitle := "Malicious <script>alert('XSS')</script> notification details"
		mockThread := &github.Notification{
			ID: github.Ptr("123"),
			Subject: &github.NotificationSubject{
				Title: github.Ptr(maliciousTitle),
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotificationsThreadsByThreadID: mockResponse(t, http.StatusOK, mockThread),
		})

		serverTool := GetNotificationDetails(translations.NullTranslationHelper)
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		handler := serverTool.Handler(deps)
		request := createMCPRequest(map[string]interface{}{
			"notificationID": "123",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		require.NoError(t, err)

		// If sanitized, the <script> tag should be removed
		assert.NotContains(t, *returned.Subject.Title, "<script>")
		assert.Equal(t, "Malicious  notification details", *returned.Subject.Title)
	})
}
