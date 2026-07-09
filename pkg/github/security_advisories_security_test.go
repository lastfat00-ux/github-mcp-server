package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SecurityAdvisoriesXSS(t *testing.T) {
	maliciousPayload := "<script>alert('XSS')</script>Safe Content"
	sanitizedPayload := "Safe Content"

	mockGlobalAdvisory := &github.GlobalSecurityAdvisory{
		SecurityAdvisory: github.SecurityAdvisory{
			GHSAID:      github.Ptr("GHSA-xxxx-xxxx-xxxx"),
			Summary:     github.Ptr(maliciousPayload),
			Description: github.Ptr(maliciousPayload),
			Severity:    github.Ptr("high"),
		},
	}

	mockRepoAdvisory := &github.SecurityAdvisory{
		GHSAID:      github.Ptr("GHSA-yyyy-yyyy-yyyy"),
		Summary:     github.Ptr(maliciousPayload),
		Description: github.Ptr(maliciousPayload),
		Severity:    github.Ptr("medium"),
	}

	tests := []struct {
		name       string
		toolDef    func(translations.TranslationHelperFunc) inventory.ServerTool
		endpoint   string
		mockResp   any
		args       map[string]any
		fieldCheck func(t *testing.T, text string)
	}{
		{
			name:     "list_global_security_advisories",
			toolDef:  ListGlobalSecurityAdvisories,
			endpoint: GetAdvisories,
			mockResp: []*github.GlobalSecurityAdvisory{mockGlobalAdvisory},
			args:     map[string]any{},
			fieldCheck: func(t *testing.T, text string) {
				assert.Contains(t, text, sanitizedPayload)
				assert.NotContains(t, text, "<script>")
			},
		},
		{
			name:     "get_global_security_advisory",
			toolDef:  GetGlobalSecurityAdvisory,
			endpoint: GetAdvisoriesByGhsaID,
			mockResp: mockGlobalAdvisory,
			args:     map[string]any{"ghsaId": "GHSA-xxxx-xxxx-xxxx"},
			fieldCheck: func(t *testing.T, text string) {
				assert.Contains(t, text, sanitizedPayload)
				assert.NotContains(t, text, "<script>")
			},
		},
		{
			name:     "list_repository_security_advisories",
			toolDef:  ListRepositorySecurityAdvisories,
			endpoint: GetReposSecurityAdvisoriesByOwnerByRepo,
			mockResp: []*github.SecurityAdvisory{mockRepoAdvisory},
			args:     map[string]any{"owner": "owner", "repo": "repo"},
			fieldCheck: func(t *testing.T, text string) {
				assert.Contains(t, text, sanitizedPayload)
				assert.NotContains(t, text, "<script>")
			},
		},
		{
			name:     "list_org_repository_security_advisories",
			toolDef:  ListOrgRepositorySecurityAdvisories,
			endpoint: GetOrgsSecurityAdvisoriesByOrg,
			mockResp: []*github.SecurityAdvisory{mockRepoAdvisory},
			args:     map[string]any{"org": "org"},
			fieldCheck: func(t *testing.T, text string) {
				assert.Contains(t, text, sanitizedPayload)
				assert.NotContains(t, text, "<script>")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toolDef := tc.toolDef(translations.NullTranslationHelper)
			mockClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.endpoint: mockResponse(t, http.StatusOK, tc.mockResp),
			})

			client := github.NewClient(mockClient)
			deps := BaseDeps{Client: client}
			handler := toolDef.Handler(deps)
			request := createMCPRequest(tc.args)

			result, err := handler(ContextWithDeps(context.Background(), deps), &request)
			require.NoError(t, err)

			textContent := getTextResult(t, result)
			tc.fieldCheck(t, textContent.Text)
		})
	}
}

func Test_StarredRepositoriesXSS(t *testing.T) {
	maliciousPayload := "<script>alert('XSS')</script>Safe Content"
	sanitizedPayload := "Safe Content"

	mockStarredRepo := &github.StarredRepository{
		Repository: &github.Repository{
			ID:          github.Ptr(int64(123)),
			Name:        github.Ptr("malicious-repo"),
			FullName:    github.Ptr("owner/malicious-repo"),
			Description: github.Ptr(maliciousPayload),
		},
	}

	toolDef := ListStarredRepositories(translations.NullTranslationHelper)
	mockClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetUserStarred: mockResponse(t, http.StatusOK, []*github.StarredRepository{mockStarredRepo}),
	})

	client := github.NewClient(mockClient)
	deps := BaseDeps{Client: client}
	handler := toolDef.Handler(deps)
	request := createMCPRequest(nil)

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)

	textContent := getTextResult(t, result)
	assert.Contains(t, textContent.Text, sanitizedPayload)
	assert.NotContains(t, textContent.Text, "<script>")
}
