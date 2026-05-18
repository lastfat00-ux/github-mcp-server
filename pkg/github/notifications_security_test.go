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

func Test_Notifications_Sanitization(t *testing.T) {
	maliciousTitle := "<script>alert('xss')</script><b>Safe</b> Title"

	mockNotification := &github.Notification{
		ID: github.Ptr("123"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr(maliciousTitle),
		},
	}

	t.Run("ListNotifications sanitizes Subject.Title", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotifications: mockResponse(t, http.StatusOK, []*github.Notification{mockNotification}),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}

		serverTool := ListNotifications(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)
		request := createMCPRequest(nil)
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var notifications []*github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &notifications)
		require.NoError(t, err)
		require.Len(t, notifications, 1)

		// If we haven't implemented it yet, this should fail.
		assert.NotContains(t, *notifications[0].Subject.Title, "<script>")
		assert.Contains(t, *notifications[0].Subject.Title, "Safe")
	})

	t.Run("GetNotificationDetails sanitizes Subject.Title", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotificationsThreadsByThreadID: mockResponse(t, http.StatusOK, mockNotification),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}

		serverTool := GetNotificationDetails(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)
		request := createMCPRequest(map[string]interface{}{
			"notificationID": "123",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var notification github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &notification)
		require.NoError(t, err)

		assert.NotContains(t, *notification.Subject.Title, "<script>")
		assert.Contains(t, *notification.Subject.Title, "Safe")
	})
}
