package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotificationsSecurity(t *testing.T) {
	mal := "Hi <script>alert(1)</script>"
	exp := "Hi "
	mock := &github.Notification{ID: github.Ptr("1"), Subject: &github.NotificationSubject{Title: github.Ptr(mal)}}
	cl := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetNotifications:                  mockResponse(t, 200, []*github.Notification{mock}),
		GetNotificationsThreadsByThreadID: mockResponse(t, 200, mock),
	}))
	deps := BaseDeps{Client: cl}
	ctx := ContextWithDeps(context.Background(), deps)
	t.Run("list", func(t *testing.T) {
		tool := ListNotifications(translations.NullTranslationHelper)
		req := createMCPRequest(nil)
		res, err := tool.Handler(deps)(ctx, &req)
		require.NoError(t, err)
		assert.Contains(t, getTextResult(t, res).Text, exp)
		assert.NotContains(t, getTextResult(t, res).Text, "<script>")
	})
	t.Run("detail", func(t *testing.T) {
		tool := GetNotificationDetails(translations.NullTranslationHelper)
		req := createMCPRequest(map[string]any{"notificationID": "1"})
		res, err := tool.Handler(deps)(ctx, &req)
		require.NoError(t, err)
		assert.Contains(t, getTextResult(t, res).Text, exp)
		assert.NotContains(t, getTextResult(t, res).Text, "<script>")
	})
}
