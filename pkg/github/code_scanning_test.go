package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/internal/toolsnaps"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetCodeScanningAlert(t *testing.T) {
	// Verify tool definition once
	toolDef := GetCodeScanningAlert(translations.NullTranslationHelper)
	require.NoError(t, toolsnaps.Test(toolDef.Tool.Name, toolDef.Tool))

	assert.Equal(t, "get_code_scanning_alert", toolDef.Tool.Name)
	assert.NotEmpty(t, toolDef.Tool.Description)

	// InputSchema is of type any, need to cast to *jsonschema.Schema
	schema, ok := toolDef.Tool.InputSchema.(*jsonschema.Schema)
	require.True(t, ok, "InputSchema should be *jsonschema.Schema")
	assert.Contains(t, schema.Properties, "owner")
	assert.Contains(t, schema.Properties, "repo")
	assert.Contains(t, schema.Properties, "alertNumber")
	assert.ElementsMatch(t, schema.Required, []string{"owner", "repo", "alertNumber"})

	// Setup mock alert for success case
	mockAlert := &github.Alert{
		Number:  github.Ptr(42),
		State:   github.Ptr("open"),
		Rule:    &github.Rule{ID: github.Ptr("test-rule"), Description: github.Ptr("Test Rule Description")},
		HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/42"),
	}

	mockXSSAlert := &github.Alert{
		Number:           github.Ptr(44),
		State:            github.Ptr("open"),
		RuleDescription:  github.Ptr("Rule <script>alert('xss')</script> Description"),
		DismissedComment: github.Ptr("Dismissed <img src=x onerror=alert('xss')>"),
		Rule: &github.Rule{
			ID:              github.Ptr("xss-rule"),
			Description:     github.Ptr("Description <script>alert('xss')</script>"),
			FullDescription: github.Ptr("Full Description <script>alert('xss')</script>"),
			Help:            github.Ptr("Help <script>alert('xss')</script>"),
			Name:            github.Ptr("Name <script>alert('xss')</script>"),
		},
		HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/44"),
	}

	expectedXSSAlert := &github.Alert{
		Number:           github.Ptr(44),
		State:            github.Ptr("open"),
		RuleDescription:  github.Ptr("Rule  Description"),
		DismissedComment: github.Ptr("Dismissed <img src=\"x\">"),
		Rule: &github.Rule{
			ID:              github.Ptr("xss-rule"),
			Description:     github.Ptr("Description "),
			FullDescription: github.Ptr("Full Description "),
			Help:            github.Ptr("Help "),
			Name:            github.Ptr("Name "),
		},
		HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/44"),
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedAlert  *github.Alert
		expectedErrMsg string
	}{
		{
			name: "successful alert fetch",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockAlert),
			}),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(42),
			},
			expectError:   false,
			expectedAlert: mockAlert,
		},
		{
			name: "successful alert fetch with sanitization",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: mockResponse(t, http.StatusOK, mockXSSAlert),
			}),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(44),
			},
			expectError:   false,
			expectedAlert: expectedXSSAlert,
		},
		{
			name: "alert fetch fails",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message": "Not Found"}`))
				}),
			}),
			requestArgs: map[string]interface{}{
				"owner":       "owner",
				"repo":        "repo",
				"alertNumber": float64(9999),
			},
			expectError:    true,
			expectedErrMsg: "failed to get alert",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			handler := toolDef.Handler(deps)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler with new signature
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			// Verify results
			if tc.expectError {
				require.NoError(t, err)
				require.True(t, result.IsError)
				errorContent := getErrorResult(t, result)
				assert.Contains(t, errorContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			require.False(t, result.IsError)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedAlert github.Alert
			err = json.Unmarshal([]byte(textContent.Text), &returnedAlert)
			assert.NoError(t, err)
			assert.Equal(t, *tc.expectedAlert.Number, *returnedAlert.Number)
			assert.Equal(t, *tc.expectedAlert.State, *returnedAlert.State)
			assert.Equal(t, *tc.expectedAlert.Rule.ID, *returnedAlert.Rule.ID)
			assert.Equal(t, *tc.expectedAlert.HTMLURL, *returnedAlert.HTMLURL)

			if tc.expectedAlert.RuleDescription != nil {
				assert.Equal(t, *tc.expectedAlert.RuleDescription, *returnedAlert.RuleDescription)
			}
			if tc.expectedAlert.DismissedComment != nil {
				assert.Equal(t, *tc.expectedAlert.DismissedComment, *returnedAlert.DismissedComment)
			}
			if tc.expectedAlert.Rule != nil {
				if tc.expectedAlert.Rule.Description != nil {
					assert.Equal(t, *tc.expectedAlert.Rule.Description, *returnedAlert.Rule.Description)
				}
				if tc.expectedAlert.Rule.FullDescription != nil {
					assert.Equal(t, *tc.expectedAlert.Rule.FullDescription, *returnedAlert.Rule.FullDescription)
				}
				if tc.expectedAlert.Rule.Help != nil {
					assert.Equal(t, *tc.expectedAlert.Rule.Help, *returnedAlert.Rule.Help)
				}
				if tc.expectedAlert.Rule.Name != nil {
					assert.Equal(t, *tc.expectedAlert.Rule.Name, *returnedAlert.Rule.Name)
				}
			}

		})
	}
}

func Test_ListCodeScanningAlerts(t *testing.T) {
	// Verify tool definition once
	toolDef := ListCodeScanningAlerts(translations.NullTranslationHelper)
	require.NoError(t, toolsnaps.Test(toolDef.Tool.Name, toolDef.Tool))

	assert.Equal(t, "list_code_scanning_alerts", toolDef.Tool.Name)
	assert.NotEmpty(t, toolDef.Tool.Description)

	// InputSchema is of type any, need to cast to *jsonschema.Schema
	schema, ok := toolDef.Tool.InputSchema.(*jsonschema.Schema)
	require.True(t, ok, "InputSchema should be *jsonschema.Schema")
	assert.Contains(t, schema.Properties, "owner")
	assert.Contains(t, schema.Properties, "repo")
	assert.Contains(t, schema.Properties, "ref")
	assert.Contains(t, schema.Properties, "state")
	assert.Contains(t, schema.Properties, "severity")
	assert.Contains(t, schema.Properties, "tool_name")
	assert.ElementsMatch(t, schema.Required, []string{"owner", "repo"})

	// Setup mock alerts for success case
	mockAlerts := []*github.Alert{
		{
			Number:  github.Ptr(42),
			State:   github.Ptr("open"),
			Rule:    &github.Rule{ID: github.Ptr("test-rule-1"), Description: github.Ptr("Test Rule 1")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/42"),
		},
		{
			Number:  github.Ptr(43),
			State:   github.Ptr("fixed"),
			Rule:    &github.Rule{ID: github.Ptr("test-rule-2"), Description: github.Ptr("Test Rule 2")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/43"),
		},
	}

	mockXSSAlerts := []*github.Alert{
		{
			Number:  github.Ptr(44),
			Rule:    &github.Rule{ID: github.Ptr("xss-rule"), Description: github.Ptr("Description <script>alert('xss')</script>")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/44"),
		},
	}

	expectedXSSAlerts := []*github.Alert{
		{
			Number:  github.Ptr(44),
			Rule:    &github.Rule{ID: github.Ptr("xss-rule"), Description: github.Ptr("Description ")},
			HTMLURL: github.Ptr("https://github.com/owner/repo/security/code-scanning/44"),
		},
	}

	tests := []struct {
		name           string
		mockedClient   *http.Client
		requestArgs    map[string]interface{}
		expectError    bool
		expectedAlerts []*github.Alert
		expectedErrMsg string
	}{
		{
			name: "successful alerts listing",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepo: expectQueryParams(t, map[string]string{
					"ref":       "main",
					"state":     "open",
					"severity":  "high",
					"tool_name": "codeql",
				}).andThen(
					mockResponse(t, http.StatusOK, mockAlerts),
				),
			}),
			requestArgs: map[string]interface{}{
				"owner":     "owner",
				"repo":      "repo",
				"ref":       "main",
				"state":     "open",
				"severity":  "high",
				"tool_name": "codeql",
			},
			expectError:    false,
			expectedAlerts: mockAlerts,
		},
		{
			name: "successful alerts listing with sanitization",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepo: mockResponse(t, http.StatusOK, mockXSSAlerts),
			}),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:    false,
			expectedAlerts: expectedXSSAlerts,
		},
		{
			name: "alerts listing fails",
			mockedClient: MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
				GetReposCodeScanningAlertsByOwnerByRepo: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"message": "Unauthorized access"}`))
				}),
			}),
			requestArgs: map[string]interface{}{
				"owner": "owner",
				"repo":  "repo",
			},
			expectError:    true,
			expectedErrMsg: "failed to list alerts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup client with mock
			client := github.NewClient(tc.mockedClient)
			deps := BaseDeps{
				Client: client,
			}
			handler := toolDef.Handler(deps)

			// Create call request
			request := createMCPRequest(tc.requestArgs)

			// Call handler with new signature
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			// Verify results
			if tc.expectError {
				require.NoError(t, err)
				require.True(t, result.IsError)
				errorContent := getErrorResult(t, result)
				assert.Contains(t, errorContent.Text, tc.expectedErrMsg)
				return
			}

			require.NoError(t, err)
			require.False(t, result.IsError)

			// Parse the result and get the text content if no error
			textContent := getTextResult(t, result)

			// Unmarshal and verify the result
			var returnedAlerts []*github.Alert
			err = json.Unmarshal([]byte(textContent.Text), &returnedAlerts)
			assert.NoError(t, err)
			assert.Len(t, returnedAlerts, len(tc.expectedAlerts))
			for i, alert := range returnedAlerts {
				assert.Equal(t, *tc.expectedAlerts[i].Number, *alert.Number)
				if tc.expectedAlerts[i].State != nil {
					assert.Equal(t, *tc.expectedAlerts[i].State, *alert.State)
				}
				assert.Equal(t, *tc.expectedAlerts[i].Rule.ID, *alert.Rule.ID)
				assert.Equal(t, *tc.expectedAlerts[i].HTMLURL, *alert.HTMLURL)

				if tc.expectedAlerts[i].Rule.Description != nil {
					assert.Equal(t, *tc.expectedAlerts[i].Rule.Description, *alert.Rule.Description)
				}
			}
		})
	}
}
