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
	// Malicious payload
	maliciousHTML := "<script>alert('xss')</script><b>Safe</b>"
	expectedSanitized := "<b>Safe</b>" // bluemonday policy in pkg/sanitize allows <b> but strips <script>

	mockAlert := &github.Alert{
		Number:          github.Ptr(42),
		RuleDescription: github.Ptr(maliciousHTML),
		DismissedComment: github.Ptr(maliciousHTML),
		Rule: &github.Rule{
			ID:              github.Ptr("test-rule"),
			Description:     github.Ptr(maliciousHTML),
			FullDescription: github.Ptr(maliciousHTML),
			Help:            github.Ptr(maliciousHTML),
		},
		HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/42"),
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}

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

	assert.NotContains(t, textContent.Text, "<script>", "Output should not contain <script> tags")

	var returnedAlert github.Alert
	err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
	assert.NoError(t, err)

	assert.Equal(t, expectedSanitized, *returnedAlert.RuleDescription)
	assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Description)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.FullDescription)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Help)
}
