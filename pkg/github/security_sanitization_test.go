package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurity_Sanitization(t *testing.T) {
	malicious := "<script>alert('xss')</script>Safe"
	expected := "Safe"

	tests := []struct {
		name    string
		toolDef func(translations.TranslationHelperFunc) inventory.ServerTool
		mockURL string
		mockObj any
		check   func(t *testing.T, resultText string)
	}{
		{
			name:    "dependabot",
			toolDef: GetDependabotAlert,
			mockURL: GetReposDependabotAlertsByOwnerByRepoByAlertNumber,
			mockObj: &github.DependabotAlert{
				DismissedComment: github.Ptr(malicious),
				SecurityAdvisory: &github.DependabotSecurityAdvisory{Summary: github.Ptr(malicious)},
			},
			check: func(t *testing.T, res string) {
				var a github.DependabotAlert
				require.NoError(t, json.Unmarshal([]byte(res), &a))
				assert.Equal(t, expected, *a.DismissedComment)
				assert.Equal(t, expected, *a.SecurityAdvisory.Summary)
			},
		},
		{
			name:    "secret_scanning",
			toolDef: GetSecretScanningAlert,
			mockURL: GetReposSecretScanningAlertsByOwnerByRepoByAlertNumber,
			mockObj: &github.SecretScanningAlert{ResolutionComment: github.Ptr(malicious)},
			check: func(t *testing.T, res string) {
				var a github.SecretScanningAlert
				require.NoError(t, json.Unmarshal([]byte(res), &a))
				assert.Equal(t, expected, *a.ResolutionComment)
			},
		},
		{
			name:    "code_scanning",
			toolDef: GetCodeScanningAlert,
			mockURL: GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber,
			mockObj: &github.Alert{RuleDescription: github.Ptr(malicious)},
			check: func(t *testing.T, res string) {
				var a github.Alert
				require.NoError(t, json.Unmarshal([]byte(res), &a))
				assert.Equal(t, expected, *a.RuleDescription)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := tt.toolDef(translations.NullTranslationHelper)
			mc := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{tt.mockURL: mockResponse(t, http.StatusOK, tt.mockObj)})
			deps := BaseDeps{Client: github.NewClient(mc)}
			req := createMCPRequest(map[string]any{"owner": "o", "repo": "r", "alertNumber": 1.0})
			res, err := tool.Handler(deps)(ContextWithDeps(context.Background(), deps), &req)
			require.NoError(t, err)
			tt.check(t, getTextResult(t, res).Text)
		})
	}
}
