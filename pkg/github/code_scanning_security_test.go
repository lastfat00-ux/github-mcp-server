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
	malicious := "<script>alert('xss')</script><b>Safe</b>"
	expected := "<b>Safe</b>"
	mockAlert := &github.Alert{
		Number: github.Ptr(42), RuleDescription: github.Ptr(malicious), DismissedComment: github.Ptr(malicious),
		Rule: &github.Rule{Description: github.Ptr(malicious), FullDescription: github.Ptr(malicious), Help: github.Ptr(malicious)},
	}

	t.Run("GetCodeScanningAlert", func(t *testing.T) {
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		}))
		deps := BaseDeps{Client: client}
		tool := GetCodeScanningAlert(translations.NullTranslationHelper)
		request := createMCPRequest(map[string]any{"owner": "o", "repo": "r", "alertNumber": 42.0})
		res, err := tool.Handler(deps)(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		var alert github.Alert
		err = json.Unmarshal([]byte(getTextResult(t, res).Text), &alert)
		require.NoError(t, err)
		assert.Equal(t, expected, *alert.RuleDescription)
		assert.Equal(t, expected, *alert.Rule.Help)
	})

	t.Run("ListCodeScanningAlerts", func(t *testing.T) {
		client := github.NewClient(MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposCodeScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, []*github.Alert{mockAlert}),
		}))
		deps := BaseDeps{Client: client}
		tool := ListCodeScanningAlerts(translations.NullTranslationHelper)
		request := createMCPRequest(map[string]any{"owner": "o", "repo": "r"})
		res, err := tool.Handler(deps)(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		var alerts []*github.Alert
		err = json.Unmarshal([]byte(getTextResult(t, res).Text), &alerts)
		require.NoError(t, err)
		assert.Equal(t, expected, *alerts[0].RuleDescription)
		assert.Equal(t, expected, *alerts[0].Rule.Help)
	})
}
