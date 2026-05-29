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

func Test_NotificationsSecurity(t *testing.T) {
	maliciousTitle := "Exploit <script>alert('xss')</script> Title"
	sanitizedTitle := "Exploit  Title"

	mockNotification := &github.Notification{
		ID:     github.Ptr("123"),
		Reason: github.Ptr("mention"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr(maliciousTitle),
		},
	}

	t.Run("ListNotifications sanitizes titles", func(t *testing.T) {
		serverTool := ListNotifications(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotifications: mockResponse(t, http.StatusOK, []*github.Notification{mockNotification}),
		})

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
		assert.Equal(t, sanitizedTitle, *returned[0].Subject.Title)
	})

	t.Run("GetNotificationDetails sanitizes titles", func(t *testing.T) {
		serverTool := GetNotificationDetails(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotificationsThreadsByThreadID: mockResponse(t, http.StatusOK, mockNotification),
		})

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
		assert.Equal(t, sanitizedTitle, *returned.Subject.Title)
	})
}
