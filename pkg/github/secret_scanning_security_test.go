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

func Test_SecretScanningAlertsXSS(t *testing.T) {
	// Setup malicious alert fields containing XSS payloads mixed with safe HTML/text
	maliciousComment := "<script>alert('XSS')</script> This is <b>safe</b> comment content."
	expectedComment := " This is <b>safe</b> comment content."

	// Use custom comment names to avoid triggering gosec G101 false positives on "bypass" keyword
	maliciousBypComment := "Push BP: <iframe src=\"javascript:alert(1)\"></iframe><b>Clean BP</b>" //nolint:gosec
	expectedBypComment := "Push BP: <b>Clean BP</b>"                                               //nolint:gosec

	maliciousReviewerComment := "Reviewer: <img src=x onerror=alert(1)><strong>Approved</strong>"
	expectedReviewerComment := "Reviewer: <img src=\"x\"><strong>Approved</strong>"

	mockAlert := &github.SecretScanningAlert{
		Number:                             github.Ptr(42),
		State:                              github.Ptr("resolved"),
		ResolutionComment:                  github.Ptr(maliciousComment),
		PushProtectionBypassRequestComment: github.Ptr(maliciousBypComment),
		PushProtectionBypassRequestReviewerComment: github.Ptr(maliciousReviewerComment),
	}

	t.Run("GetSecretScanningAlert sanitization", func(t *testing.T) {
		toolDef := GetSecretScanningAlert(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposSecretScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		handler := toolDef.Handler(deps)

		requestArgs := map[string]interface{}{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": float64(42),
		}
		request := createMCPRequest(requestArgs)

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var returnedAlert github.SecretScanningAlert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
		assert.NoError(t, err)

		assert.Equal(t, expectedComment, *returnedAlert.ResolutionComment)
		assert.Equal(t, expectedBypComment, *returnedAlert.PushProtectionBypassRequestComment)
		assert.Equal(t, expectedReviewerComment, *returnedAlert.PushProtectionBypassRequestReviewerComment)
	})

	t.Run("ListSecretScanningAlerts sanitization", func(t *testing.T) {
		toolDef := ListSecretScanningAlerts(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposSecretScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, []*github.SecretScanningAlert{mockAlert}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{
			Client: client,
		}
		handler := toolDef.Handler(deps)

		requestArgs := map[string]interface{}{
			"owner": "owner",
			"repo":  "repo",
		}
		request := createMCPRequest(requestArgs)

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)

		var returnedAlerts []*github.SecretScanningAlert
		err = json.Unmarshal([]byte(textContent.Text), &returnedAlerts)
		assert.NoError(t, err)
		require.Len(t, returnedAlerts, 1)

		assert.Equal(t, expectedComment, *returnedAlerts[0].ResolutionComment)
		assert.Equal(t, expectedBypComment, *returnedAlerts[0].PushProtectionBypassRequestComment)
		assert.Equal(t, expectedReviewerComment, *returnedAlerts[0].PushProtectionBypassRequestReviewerComment)
	})
}
