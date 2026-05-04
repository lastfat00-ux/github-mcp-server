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

func TestCodeScanningXSSSanitization(t *testing.T) {
	toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)

	maliciousAlert := &github.Alert{
		Number:           github.Ptr(1),
		RuleDescription:  github.Ptr("Alert with <script>alert('xss')</script>"),
		Rule:             &github.Rule{Description: github.Ptr("Rule with <img src=x onerror=alert(1)>")},
		DismissedComment: github.Ptr("Dismissed with <a href='javascript:alert(1)'>click me</a>"),
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, maliciousAlert),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{Client: client}
	handler := toolDef.Handler(deps)

	request := createMCPRequest(map[string]interface{}{
		"owner":       "owner",
		"repo":        "repo",
		"alertNumber": float64(1),
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	var returnedAlert github.Alert
	err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedAlert)
	require.NoError(t, err)

	assert.NotContains(t, *returnedAlert.RuleDescription, "<script>")
	assert.NotContains(t, *returnedAlert.Rule.Description, "onerror")
	assert.NotContains(t, *returnedAlert.DismissedComment, "javascript:")
}

func TestDependabotXSSSanitization(t *testing.T) {
	toolDef := GetDependabotAlert(translations.NullTranslationHelper)

	maliciousAlert := &github.DependabotAlert{
		Number: github.Ptr(1),
		SecurityAdvisory: &github.DependabotSecurityAdvisory{
			Summary:     github.Ptr("Summary with <script>alert('xss')</script>"),
			Description: github.Ptr("Description with <iframe src='javascript:alert(1)'></iframe>"),
		},
		DismissedComment: github.Ptr("Dismissed with <svg/onload=alert(1)>"),
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposDependabotAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, maliciousAlert),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{Client: client}
	handler := toolDef.Handler(deps)

	request := createMCPRequest(map[string]interface{}{
		"owner":       "owner",
		"repo":        "repo",
		"alertNumber": float64(1),
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	var returnedAlert github.DependabotAlert
	err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedAlert)
	require.NoError(t, err)

	assert.NotContains(t, *returnedAlert.SecurityAdvisory.Summary, "<script>")
	assert.NotContains(t, *returnedAlert.SecurityAdvisory.Description, "iframe")
	assert.NotContains(t, *returnedAlert.DismissedComment, "<svg")
}

func TestSecretScanningXSSSanitization(t *testing.T) {
	toolDef := GetSecretScanningAlert(translations.NullTranslationHelper)

	maliciousAlert := &github.SecretScanningAlert{
		Number:                                 github.Ptr(1),
		ResolutionComment:                      github.Ptr("Comment with <script>alert('xss')</script>"),
		PushProtectionBypassRequestComment:     github.Ptr("Request with <img src=x onerror=alert(1)>"),
		PushProtectionBypassRequestReviewerComment: github.Ptr("Reviewer with <a href='javascript:alert(1)'>link</a>"),
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposSecretScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, maliciousAlert),
	})

	client := github.NewClient(mockedClient)
	deps := BaseDeps{Client: client}
	handler := toolDef.Handler(deps)

	request := createMCPRequest(map[string]interface{}{
		"owner":       "owner",
		"repo":        "repo",
		"alertNumber": float64(1),
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	var returnedAlert github.SecretScanningAlert
	err = json.Unmarshal([]byte(getTextResult(t, result).Text), &returnedAlert)
	require.NoError(t, err)

	assert.NotContains(t, *returnedAlert.ResolutionComment, "<script>")
	assert.NotContains(t, *returnedAlert.PushProtectionBypassRequestComment, "onerror")
	assert.NotContains(t, *returnedAlert.PushProtectionBypassRequestReviewerComment, "javascript:")
}
