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

func TestNotificationsSecurity(t *testing.T) {
	malicious := "Hello <script>alert('xss')</script> world"
	expected := "Hello  world"
	mock := &github.Notification{ID: github.Ptr("123"), Subject: &github.NotificationSubject{Title: github.Ptr(malicious)}}

	client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetNotifications:                  mockResponse(t, 200, []*github.Notification{mock}),
		GetNotificationsThreadsByThreadID: mockResponse(t, 200, mock),
	}))
	deps := BaseDeps{Client: client}
	ctx := ContextWithDeps(context.Background(), deps)

	t.Run("list_notifications", func(t *testing.T) {
		tool := ListNotifications(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		req := createMCPRequest(map[string]any{})
		res, err := handler(ctx, &req)
		require.NoError(t, err)
		var list []*github.Notification
		err = json.Unmarshal([]byte(getTextResult(t, res).Text), &list)
		require.NoError(t, err)
		assert.Equal(t, expected, *list[0].Subject.Title)
	})

	t.Run("get_notification_details", func(t *testing.T) {
		tool := GetNotificationDetails(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		req := createMCPRequest(map[string]any{"notificationID": "123"})
		res, err := handler(ctx, &req)
		require.NoError(t, err)
		var detail github.Notification
		err = json.Unmarshal([]byte(getTextResult(t, res).Text), &detail)
		require.NoError(t, err)
		assert.Equal(t, expected, *detail.Subject.Title)
	})
}
