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

func TestSecurity_DependabotSanitization(t *testing.T) {
	malicious := "<script>alert('xss')</script>Malicious content"
	expected := "Malicious content"

	mockAlert := &github.DependabotAlert{
		Number:           github.Ptr(1),
		DismissedComment: github.Ptr(malicious),
		SecurityAdvisory: &github.DependabotSecurityAdvisory{
			Summary:     github.Ptr(malicious),
			Description: github.Ptr(malicious),
		},
	}

	toolDef := GetDependabotAlert(translations.NullTranslationHelper)
	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposDependabotAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
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

	textContent := getTextResult(t, result)
	var returnedAlert github.DependabotAlert
	err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
	assert.NoError(t, err)

	assert.Equal(t, expected, *returnedAlert.DismissedComment, "DismissedComment should be sanitized")
	assert.Equal(t, expected, *returnedAlert.SecurityAdvisory.Summary, "Summary should be sanitized")
	assert.Equal(t, expected, *returnedAlert.SecurityAdvisory.Description, "Description should be sanitized")
}

func TestSecurity_SecretScanningSanitization(t *testing.T) {
	malicious := "<script>alert('xss')</script>Malicious content"
	expected := "Malicious content"

	mockAlert := &github.SecretScanningAlert{
		Number:            github.Ptr(1),
		ResolutionComment: github.Ptr(malicious),
	}

	toolDef := GetSecretScanningAlert(translations.NullTranslationHelper)
	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposSecretScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
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

	textContent := getTextResult(t, result)
	var returnedAlert github.SecretScanningAlert
	err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
	assert.NoError(t, err)

	assert.Equal(t, expected, *returnedAlert.ResolutionComment, "ResolutionComment should be sanitized")
}

func TestSecurity_CodeScanningSanitization(t *testing.T) {
	malicious := "<script>alert('xss')</script>Malicious content"
	expected := "Malicious content"

	mockAlert := &github.Alert{
		Number:           github.Ptr(1),
		RuleDescription:  github.Ptr(malicious),
		DismissedComment: github.Ptr(malicious),
		Rule: &github.Rule{
			Description:     github.Ptr(malicious),
			FullDescription: github.Ptr(malicious),
			Help:            github.Ptr(malicious),
			Name:            github.Ptr(malicious),
		},
	}

	toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
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

	textContent := getTextResult(t, result)
	var returnedAlert github.Alert
	err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
	assert.NoError(t, err)

	assert.Equal(t, expected, *returnedAlert.RuleDescription, "RuleDescription should be sanitized")
	assert.Equal(t, expected, *returnedAlert.DismissedComment, "DismissedComment should be sanitized")
	assert.Equal(t, expected, *returnedAlert.Rule.Description, "Rule.Description should be sanitized")
	assert.Equal(t, expected, *returnedAlert.Rule.FullDescription, "Rule.FullDescription should be sanitized")
	assert.Equal(t, expected, *returnedAlert.Rule.Help, "Rule.Help should be sanitized")
	assert.Equal(t, expected, *returnedAlert.Rule.Name, "Rule.Name should be sanitized")
}
