package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	gogh "github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeScanningAlertXSS(t *testing.T) {
	maliciousInput := "<script>alert('xss')</script><b>Safe HTML</b>"
	expectedSanitized := "<b>Safe HTML</b>"

	mockAlert := &gogh.Alert{
		Number:           gogh.Ptr(101),
		State:            gogh.Ptr("open"),
		RuleDescription:  gogh.Ptr(maliciousInput),
		DismissedComment: gogh.Ptr(maliciousInput),
		Rule: &gogh.Rule{
			ID:              gogh.Ptr("rule-xss"),
			Description:     gogh.Ptr(maliciousInput),
			FullDescription: gogh.Ptr(maliciousInput),
			Help:            gogh.Ptr(maliciousInput),
		},
		HTMLURL: gogh.Ptr("https://github.com/owner/repo/security/code-scanning/101"),
	}

	t.Run("GetCodeScanningAlert sanitizes XSS", func(t *testing.T) {
		toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		})

		client := gogh.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(101),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var returnedAlert gogh.Alert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		require.NoError(t, err)

		assert.Equal(t, expectedSanitized, *returnedAlert.RuleDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
		require.NotNil(t, returnedAlert.Rule)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Description)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Help)
	})

	t.Run("ListCodeScanningAlerts sanitizes XSS", func(t *testing.T) {
		toolDef := ListCodeScanningAlerts(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, []*gogh.Alert{mockAlert}),
		})

		client := gogh.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner": "owner",
			"repo":  "repo",
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var returnedAlerts []*gogh.Alert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlerts)
		require.NoError(t, err)
		require.Len(t, returnedAlerts, 1)

		alert := returnedAlerts[0]
		assert.Equal(t, expectedSanitized, *alert.RuleDescription)
		assert.Equal(t, expectedSanitized, *alert.DismissedComment)
		require.NotNil(t, alert.Rule)
		assert.Equal(t, expectedSanitized, *alert.Rule.Description)
		assert.Equal(t, expectedSanitized, *alert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *alert.Rule.Help)
	})
}
