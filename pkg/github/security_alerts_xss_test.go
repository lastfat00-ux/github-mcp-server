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

func Test_SecurityAlertsXSS(t *testing.T) {
	maliciousPayload := "Hello <script>alert('XSS')</script><b>World</b>"
	expectedSanitized := "Hello <b>World</b>"

	t.Run("DependabotAlert XSS", func(t *testing.T) {
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

	t.Run("SecretScanningAlert XSS", func(t *testing.T) {
		mockAlert := &github.SecretScanningAlert{
			Number:                             github.Ptr(1),
			ResolutionComment:                  github.Ptr(maliciousPayload),
			PushProtectionBypassRequestComment: github.Ptr(maliciousPayload),
			PushProtectionBypassRequestReviewerComment: github.Ptr(maliciousPayload),
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
		assert.Equal(t, expectedSanitized, *returnedAlert.PushProtectionBypassRequestComment)
		assert.Equal(t, expectedSanitized, *returnedAlert.PushProtectionBypassRequestReviewerComment)
	})
}
