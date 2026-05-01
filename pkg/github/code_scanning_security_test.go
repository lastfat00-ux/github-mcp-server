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

func Test_CodeScanningXSSSanitization(t *testing.T) {
	maliciousPayload := "<script>alert('xss')</script>Malicious"
	expectedSanitized := "Malicious"

	mockAlert := &github.Alert{
		Number:           github.Ptr(1),
		RuleDescription:  github.Ptr(maliciousPayload),
		DismissedComment: github.Ptr(maliciousPayload),
		Rule: &github.Rule{
			Description:     github.Ptr(maliciousPayload),
			FullDescription: github.Ptr(maliciousPayload),
			Help:            github.Ptr(maliciousPayload),
		},
	}

	tests := []struct {
		name        string
		toolDef     func(translations.TranslationHelperFunc) inventory.ServerTool
		requestArgs map[string]interface{}
		mockPath    string
		mockHandler http.HandlerFunc
	}{
		{
			name:    "GetCodeScanningAlert sanitizes fields",
			toolDef: GetCodeScanningAlert,
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(1),
			},
			mockPath:    GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber,
			mockHandler: mockResponse(t, http.StatusOK, mockAlert),
		},
		{
			name:    "ListCodeScanningAlerts sanitizes fields",
			toolDef: ListCodeScanningAlerts,
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			mockPath:    GetReposCodeScanningAlertsByOwnerByRepo,
			mockHandler: mockResponse(t, http.StatusOK, []*github.Alert{mockAlert}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				tc.mockPath: tc.mockHandler,
			})
			client := github.NewClient(mockedClient)
			deps := BaseDeps{Client: client}
			toolDef := tc.toolDef(translations.NullTranslationHelper)
			handler := toolDef.Handler(deps)

			request := createMCPRequest(tc.requestArgs)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			require.False(t, result.IsError)

			textContent := getTextResult(t, result)

			if tc.name == "ListCodeScanningAlerts sanitizes fields" {
				var alerts []*github.Alert
				err = json.Unmarshal([]byte(textContent.Text), &alerts)
				require.NoError(t, err)
				require.Len(t, alerts, 1)
				assertAlertSanitized(t, alerts[0], expectedSanitized)
			} else {
				var alert github.Alert
				err = json.Unmarshal([]byte(textContent.Text), &alert)
				require.NoError(t, err)
				assertAlertSanitized(t, &alert, expectedSanitized)
			}
		})
	}
}

func assertAlertSanitized(t *testing.T, alert *github.Alert, expected string) {
	assert.Equal(t, expected, *alert.RuleDescription)
	assert.Equal(t, expected, *alert.DismissedComment)
	assert.Equal(t, expected, *alert.Rule.Description)
	assert.Equal(t, expected, *alert.Rule.FullDescription)
	assert.Equal(t, expected, *alert.Rule.Help)
}
