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

func Test_CodeScanningAlertSanitization(t *testing.T) {
	maliciousHTML := "Malicious <script>alert('XSS')</script><b>Safe</b>"
	expectedSanitized := "Malicious <b>Safe</b>"

	mockAlert := &github.Alert{
		Number:           github.Ptr(42),
		RuleDescription:  github.Ptr(maliciousHTML),
		DismissedComment: github.Ptr(maliciousHTML),
		Rule: &github.Rule{
			Description:     github.Ptr(maliciousHTML),
			FullDescription: github.Ptr(maliciousHTML),
			Help:            github.Ptr(maliciousHTML),
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		GetReposCodeScanningAlertsByOwnerByRepo:              mockResponse(t, http.StatusOK, []*github.Alert{mockAlert}),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}

	t.Run("GetCodeScanningAlert sanitizes content", func(t *testing.T) {
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
		assert.NoError(t, err)

		assert.Equal(t, expectedSanitized, *returnedAlert.RuleDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Description)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Help)
	})

	t.Run("ListCodeScanningAlerts sanitizes content", func(t *testing.T) {
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
		assert.NoError(t, err)
		require.Len(t, returnedAlerts, 1)

		alert := returnedAlerts[0]
		assert.Equal(t, expectedSanitized, *alert.RuleDescription)
		assert.Equal(t, expectedSanitized, *alert.DismissedComment)
		assert.Equal(t, expectedSanitized, *alert.Rule.Description)
		assert.Equal(t, expectedSanitized, *alert.Rule.FullDescription)
		assert.Equal(t, expectedSanitized, *alert.Rule.Help)
	})
}
