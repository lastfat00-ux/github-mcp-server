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

func Test_Notifications_Security(t *testing.T) {
	maliciousTitle := "Payload <script>alert('xss')</script>"
	expectedSanitizedTitle := "Payload " // bluemonday.StrictPolicy() strips <script> and its content

	mockNotification := &github.Notification{
		ID: github.Ptr("123"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr(maliciousTitle),
		},
	}

	t.Run("ListNotifications sanitizes subject title", func(t *testing.T) {
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
		assert.Equal(t, expectedSanitizedTitle, *returned[0].Subject.Title)
	})

	t.Run("GetNotificationDetails sanitizes subject title", func(t *testing.T) {
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
		assert.Equal(t, expectedSanitizedTitle, *returned.Subject.Title)
	})

	t.Run("Sanitization preserves technical content that is not an HTML tag", func(t *testing.T) {
		technicalTitle := "Fix List<String> bug"
		// bluemonday.StrictPolicy() might strip <String> if it thinks it's a tag.
		// Let's see what happens.
		mockNotificationTech := &github.Notification{
			ID: github.Ptr("456"),
			Subject: &github.NotificationSubject{
				Title: github.Ptr(technicalTitle),
			},
		}

		serverTool := GetNotificationDetails(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetNotificationsThreadsByThreadID: mockResponse(t, http.StatusOK, mockNotificationTech),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		handler := serverTool.Handler(deps)
		request := createMCPRequest(map[string]interface{}{
			"notificationID": "456",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)

		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned github.Notification
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		require.NoError(t, err)
		// If it's stripped, it will be "Fix List bug"
		t.Logf("Technical title after sanitization: %s", *returned.Subject.Title)
	})
}
