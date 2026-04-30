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

func TestCodeScanningSanitization(t *testing.T) {
	maliciousHTML := "Hello <script>alert('xss')</script><iframe src=\"javascript:alert('xss')\"></iframe> world"
	expectedSanitized := "Hello  world"

	mockAlert := &github.Alert{
		Number:           github.Ptr(1),
		DismissedComment: github.Ptr(maliciousHTML),
		Rule: &github.Rule{
			Description:     github.Ptr(maliciousHTML),
			FullDescription: github.Ptr(maliciousHTML),
			Help:            github.Ptr(maliciousHTML),
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
	})

	toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
	client := github.NewClient(mockedClient)
	deps := BaseDeps{
		Client: client,
	}
	handler := toolDef.Handler(deps)

	requestArgs := map[string]interface{}{
		"owner":       "owner",
		"repo":        "repo",
		"alertNumber": float64(1),
	}
	request := createMCPRequest(requestArgs)

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var returnedAlert github.Alert
	err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
	require.NoError(t, err)

	assert.Equal(t, expectedSanitized, *returnedAlert.DismissedComment)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Description)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.FullDescription)
	assert.Equal(t, expectedSanitized, *returnedAlert.Rule.Help)
}
