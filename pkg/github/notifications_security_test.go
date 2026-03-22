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

func Test_ListNotifications_Sanitization(t *testing.T) {
	mockNotification := &github.Notification{
		ID:     github.Ptr("123"),
		Reason: github.Ptr("mention"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr("Exploit <script>alert('xss')</script>"),
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetNotifications: mockResponse(t, http.StatusOK, []*github.Notification{mockNotification}),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}

	serverTool := ListNotifications(translations.NullTranslationHelper)
	handler := serverTool.Handler(deps)
	request := createMCPRequest(map[string]interface{}{})
	result, err := handler(ContextWithDeps(context.Background(), deps), &request)

	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var returned []*github.Notification
	err = json.Unmarshal([]byte(textContent.Text), &returned)
	require.NoError(t, err)

	assert.Equal(t, "Exploit ", *returned[0].Subject.Title, "Notification title should be sanitized")
}

func Test_GetNotificationDetails_Sanitization(t *testing.T) {
	mockThread := &github.Notification{
		ID:     github.Ptr("123"),
		Reason: github.Ptr("mention"),
		Subject: &github.NotificationSubject{
			Title: github.Ptr("Exploit <script>alert('xss')</script>"),
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetNotificationsThreadsByThreadID: mockResponse(t, http.StatusOK, mockThread),
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
	var returned github.Notification
	err = json.Unmarshal([]byte(textContent.Text), &returned)
	require.NoError(t, err)

	assert.Equal(t, "Exploit ", *returned.Subject.Title, "Notification details title should be sanitized")
}
