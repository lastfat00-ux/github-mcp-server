package github
import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
)
func Test_Notifications_Sanitization(t *testing.T) {
	mockMalicious := &github.Notification{ID: github.Ptr("456"), Subject: &github.NotificationSubject{Title: github.Ptr("Malicious <script>alert(1)</script><b>Title</b>")}}
	serverTool := ListNotifications(translations.NullTranslationHelper)
	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{GetNotifications: mockResponse(t, http.StatusOK, []*github.Notification{mockMalicious})})
	deps := BaseDeps{Client: github.NewClient(mockedClient)}
	handler := serverTool.Handler(deps)
	req := createMCPRequest(map[string]interface{}{})
	res, _ := handler(ContextWithDeps(context.Background(), deps), &req)
	var returned []*github.Notification
	json.Unmarshal([]byte(getTextResult(t, res).Text), &returned)
	assert.Equal(t, "Malicious <b>Title</b>", *returned[0].Subject.Title)
}
