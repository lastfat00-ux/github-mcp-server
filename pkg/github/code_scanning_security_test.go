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

func TestCodeScanningAlertXSS(t *testing.T) {
	mockAlert := &github.Alert{
		Number:           github.Ptr(101),
		State:            github.Ptr("open"),
		RuleDescription:  github.Ptr("Potential XSS <script>alert('xss')</script> in <b>rule</b>"),
		DismissedComment: github.Ptr("<img src=x onerror=alert('dismissed')>Dismissed comment"),
		Rule: &github.Rule{
			ID:              github.Ptr("rule-1"),
			Description:     github.Ptr("Description <iframe src='javascript:alert(1)'></iframe>"),
			FullDescription: github.Ptr("Full description <script>evil()</script><b>safe</b>"),
			Help:            github.Ptr("Help docs <a href='javascript:alert(1)'>link</a>"),
		},
		MostRecentInstance: &github.MostRecentInstance{
			Message: &github.Message{
				Text: github.Ptr("Message <script>alert('instance')</script><b>bold</b>"),
			},
		},
	}

	t.Run("GetCodeScanningAlert sanitizes XSS payloads", func(t *testing.T) {
		toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		}))

		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)
		request := createMCPRequest(map[string]any{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(101),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var alert github.Alert
		err = json.Unmarshal([]byte(textContent.Text), &alert)
		require.NoError(t, err)

		// Assert script and dangerous tags/attributes are stripped while bluemonday-approved tags (like <b>) are preserved
		assert.NotContains(t, *alert.RuleDescription, "<script>")
		assert.Contains(t, *alert.RuleDescription, "<b>rule</b>")

		assert.NotContains(t, *alert.DismissedComment, "onerror")
		assert.Contains(t, *alert.DismissedComment, "Dismissed comment")

		assert.NotContains(t, *alert.Rule.Description, "<iframe>")
		assert.NotContains(t, *alert.Rule.FullDescription, "<script>")
		assert.Contains(t, *alert.Rule.FullDescription, "<b>safe</b>")

		assert.NotContains(t, *alert.Rule.Help, "javascript:alert")

		assert.NotContains(t, *alert.MostRecentInstance.Message.Text, "<script>")
		assert.Contains(t, *alert.MostRecentInstance.Message.Text, "<b>bold</b>")
	})

	t.Run("ListCodeScanningAlerts sanitizes XSS payloads", func(t *testing.T) {
		toolDef := ListCodeScanningAlerts(translations.NullTranslationHelper)
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, []*github.Alert{mockAlert}),
		}))

		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)
		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var alerts []*github.Alert
		err = json.Unmarshal([]byte(textContent.Text), &alerts)
		require.NoError(t, err)
		require.Len(t, alerts, 1)

		alert := alerts[0]
		assert.NotContains(t, *alert.RuleDescription, "<script>")
		assert.Contains(t, *alert.RuleDescription, "<b>rule</b>")
		assert.NotContains(t, *alert.DismissedComment, "onerror")
	})
}
