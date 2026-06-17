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

func TestNotificationsXSSSanitization(t *testing.T) {
	maliciousTitle := "Dangerous Title <script>alert('XSS')</script><img src=x onerror=alert(1)>"
	// pkg/sanitize.Sanitize uses a policy that allows <img> but strips dangerous attributes like onerror.
	// Based on the failure, <img src="x"> is kept.
	expectedTitle := "Dangerous Title <img src=\"x\">"

	mockNotification := &github.Notification{
		ID: github.Ptr("123"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr(maliciousTitle),
		},
	}

	t.Run("ListNotifications sanitizes Subject.Title", func(t *testing.T) {
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
		require.Len(t, returned, 1)

		assert.NotContains(t, *returned[0].Subject.Title, "<script>")
		assert.NotContains(t, *returned[0].Subject.Title, "onerror")
		assert.Equal(t, expectedTitle, *returned[0].Subject.Title)
	})

	t.Run("GetNotificationDetails sanitizes Subject.Title", func(t *testing.T) {
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

		assert.NotContains(t, *returned.Subject.Title, "<script>")
		assert.NotContains(t, *returned.Subject.Title, "onerror")
		assert.Equal(t, expectedTitle, *returned.Subject.Title)
	})
}
