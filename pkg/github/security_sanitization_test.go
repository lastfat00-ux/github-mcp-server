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

func Test_SecuritySanitization(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script><b>Safe</b>"
	expectedSanitized := "<b>Safe</b>"

	t.Run("DependabotAlert_Sanitization", func(t *testing.T) {
		mockAlert := &github.DependabotAlert{
			Number:           github.Ptr(1),
			DismissedComment: github.Ptr(maliciousPayload),
			SecurityAdvisory: &github.DependabotSecurityAdvisory{
				Summary:     github.Ptr(maliciousPayload),
				Description: github.Ptr(maliciousPayload),
			},
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposDependabotAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		toolDef := GetDependabotAlert(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAlert github.DependabotAlert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
		assert.Equal(t, expectedSanitized, *returnedAlert.SecurityAdvisory.Summary)
		assert.Equal(t, expectedSanitized, *returnedAlert.SecurityAdvisory.Description)
	})

	t.Run("SecretScanningAlert_Sanitization", func(t *testing.T) {
		mockAlert := &github.SecretScanningAlert{
			Number:            github.Ptr(1),
			ResolutionComment: github.Ptr(maliciousPayload),
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposSecretScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		toolDef := GetSecretScanningAlert(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAlert github.SecretScanningAlert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returnedAlert.ResolutionComment)
	})

	t.Run("SecurityAdvisory_Sanitization", func(t *testing.T) {
		mockAdvisory := &github.SecurityAdvisory{
			GHSAID:      github.Ptr("GHSA-1"),
			Summary:     github.Ptr(maliciousPayload),
			Description: github.Ptr(maliciousPayload),
		}

		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetAdvisoriesByGhsaID: mockResponse(t, http.StatusOK, mockAdvisory),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		toolDef := GetGlobalSecurityAdvisory(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]interface{}{
			"ghsaId": "GHSA-1",
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAdvisory github.SecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &returnedAdvisory)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returnedAdvisory.Summary)
		assert.Equal(t, expectedSanitized, *returnedAdvisory.Description)
	})

	t.Run("CodeScanningAlert_Sanitization", func(t *testing.T) {
		// Since we can't easily reference github.Alert due to it being unexported from the package,
		// we use map[string]interface{} for the mock response.
		mockAlert := map[string]interface{}{
			"number":            1,
			"dismissed_comment": maliciousPayload,
		}

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
			"alertNumber": float64(1),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returnedAlert map[string]interface{}
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, returnedAlert["dismissed_comment"])
	})
}
