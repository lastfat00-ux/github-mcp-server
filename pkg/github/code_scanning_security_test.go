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

func TestCodeScanningXSS(t *testing.T) {
	maliciousPayload := "<script>alert('XSS')</script><b>Safe</b>"
	expectedSanitized := "<b>Safe</b>"
	mockAlert := &github.Alert{
		Number:           github.Ptr(1),
		RuleDescription:  github.Ptr(maliciousPayload),
		DismissedComment: github.Ptr(maliciousPayload),
		Rule: &github.Rule{Description: github.Ptr(maliciousPayload)},
	}
	mockClient := NewMockedHTTPClient(
		WithRequestMatchHandler(GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber, mockResponse(t, http.StatusOK, mockAlert)),
	)
	client := github.NewClient(mockClient)
	deps := BaseDeps{Client: client}
	tool := GetCodeScanningAlert(translations.NullTranslationHelper)
	handler := tool.Handler(deps)
	req := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo", "alertNumber": 1})
	result, err := handler(ContextWithDeps(context.Background(), deps), &req)
	require.NoError(t, err)
	content := getTextResult(t, result)
	var alert github.Alert
	json.Unmarshal([]byte(content.Text), &alert)
	assert.Equal(t, expectedSanitized, *alert.RuleDescription)
	assert.Equal(t, expectedSanitized, *alert.DismissedComment)
	assert.Equal(t, expectedSanitized, *alert.Rule.Description)
}
