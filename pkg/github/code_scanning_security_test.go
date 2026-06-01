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

func Test_CodeScanningSecuritySanitization(t *testing.T) {
	maliciousHTML := "<script>alert('xss')</script><b>Safe</b>"
	expectedSanitized := "<b>Safe</b>"

	mockAlert := &github.Alert{
		Number:          github.Ptr(42),
		RuleDescription: github.Ptr(maliciousHTML),
		DismissedComment: github.Ptr(maliciousHTML),
		Rule: &github.Rule{
			Description:     github.Ptr(maliciousHTML),
			FullDescription: github.Ptr(maliciousHTML),
			Help:            github.Ptr(maliciousHTML),
		},
	}

	t.Run("GetCodeScanningAlert sanitization", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(42),
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAlert github.Alert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		require.NoError(t, err)

		assert.Equal(t, expectedSanitized, *returnedAlert.RuleDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Description)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Help)
	})

	t.Run("ListCodeScanningAlerts sanitization", func(t *testing.T) {
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, []*github.Alert{mockAlert}),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		toolDef := ListCodeScanningAlerts(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner": "owner",
			"repo":  "repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAlerts []*github.Alert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlerts)
		require.NoError(t, err)
		require.Len(t, returnedAlerts, 1)

		alert := returnedAlerts[0]
		assert.Equal(t, expectedSanitized, *alert.RuleDescription)
		assert.Equal(t, expectedSanitized, *alert.DismissedComment)
		assert.Equal(t, expectedSanitized, *alert.Rule.Description)
		assert.Equal(t, expectedSanitized, *alert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *alert.Rule.Help)
	})
}
