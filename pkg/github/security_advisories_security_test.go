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

func TestSecurityAdvisoriesSanitization(t *testing.T) {
	ctx := context.Background()
	maliciousPayload := "Advisory with <script>alert('XSS')</script> summary"
	sanitizedPayload := "Advisory with  summary"

	mockGlobalAdvisory := &github.GlobalSecurityAdvisory{
		SecurityAdvisory: github.SecurityAdvisory{
			GHSAID:      github.Ptr("GHSA-xxxx-xxxx-xxxx"),
			Summary:     github.Ptr(maliciousPayload),
			Description: github.Ptr("Description with <img src=x onerror=alert(1)>"),
			Severity:    github.Ptr("high"),
		},
	}

	mockRepoAdvisory := &github.SecurityAdvisory{
		GHSAID:      github.Ptr("GHSA-yyyy-yyyy-yyyy"),
		Summary:     github.Ptr(maliciousPayload),
		Description: github.Ptr("Description with <img src=x onerror=alert(1)>"),
		Severity:    github.Ptr("medium"),
	}

	t.Run("ListGlobalSecurityAdvisories sanitizes output", func(t *testing.T) {
		toolDef := ListGlobalSecurityAdvisories(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetAdvisories: mockResponse(t, http.StatusOK, []*github.GlobalSecurityAdvisory{mockGlobalAdvisory}),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{})
		result, err := handler(ContextWithDeps(ctx, deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var advisories []*github.GlobalSecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &advisories)
		require.NoError(t, err)

		assert.Equal(t, sanitizedPayload, *advisories[0].Summary)
		assert.NotContains(t, *advisories[0].Description, "onerror")
	})

	t.Run("GetGlobalSecurityAdvisory sanitizes output", func(t *testing.T) {
		toolDef := GetGlobalSecurityAdvisory(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetAdvisoriesByGhsaID: mockResponse(t, http.StatusOK, mockGlobalAdvisory),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{"ghsaId": "GHSA-xxxx-xxxx-xxxx"})
		result, err := handler(ContextWithDeps(ctx, deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var advisory github.GlobalSecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &advisory)
		require.NoError(t, err)

		assert.Equal(t, sanitizedPayload, *advisory.Summary)
		assert.NotContains(t, *advisory.Description, "onerror")
	})

	t.Run("ListRepositorySecurityAdvisories sanitizes output", func(t *testing.T) {
		toolDef := ListRepositorySecurityAdvisories(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposSecurityAdvisoriesByOwnerByRepo: mockResponse(t, http.StatusOK, []*github.SecurityAdvisory{mockRepoAdvisory}),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{"owner": "owner", "repo": "repo"})
		result, err := handler(ContextWithDeps(ctx, deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var advisories []*github.SecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &advisories)
		require.NoError(t, err)

		assert.Equal(t, sanitizedPayload, *advisories[0].Summary)
		assert.NotContains(t, *advisories[0].Description, "onerror")
	})

	t.Run("ListOrgRepositorySecurityAdvisories sanitizes output", func(t *testing.T) {
		toolDef := ListOrgRepositorySecurityAdvisories(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetOrgsSecurityAdvisoriesByOrg: mockResponse(t, http.StatusOK, []*github.SecurityAdvisory{mockRepoAdvisory}),
		})
		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{"org": "org"})
		result, err := handler(ContextWithDeps(ctx, deps), &request)
		require.NoError(t, err)

		textContent := getTextResult(t, result)
		var advisories []*github.SecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &advisories)
		require.NoError(t, err)

		assert.Equal(t, sanitizedPayload, *advisories[0].Summary)
		assert.NotContains(t, *advisories[0].Description, "onerror")
	})
}
