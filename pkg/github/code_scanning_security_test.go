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

func TestCodeScanningXSS(t *testing.T) {
	maliciousPayload := "<script>alert('XSS')</script><b>Safe</b>"
	// Sanitize expected output: bluemonday.StrictPolicy() + allowed tags
	// Script tags are removed entirely along with their content by default in many policies,
	// but let's see what pkg/sanitize does.
	// pkg/sanitize.Sanitize uses StrictPolicy then allows some tags.
	// StrictPolicy strips all tags.
	expectedSanitized := "<b>Safe</b>"

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

	t.Run("GetCodeScanningAlert - verify FIX", func(t *testing.T) {
		mockClient := NewMockedHTTPClient(
			WithRequestMatchHandler(GetReposCodeScanningAlertsByOwnerByRepoByAlertNumber, mockResponse(t, http.StatusOK, mockAlert)),
		)
		client := github.NewClient(mockClient)
		deps := BaseDeps{Client: client}

		tool := GetCodeScanningAlert(translations.NullTranslationHelper)
		handler := tool.Handler(deps)

		req := createMCPRequest(map[string]any{
			"owner":       "owner",
			"repo":        "repo",
			"alertNumber": 1,
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		content := getTextResult(t, result)
		var alert github.Alert
		err = json.Unmarshal([]byte(content.Text), &alert)
		require.NoError(t, err)

		// Asserting it IS sanitized
		assert.Equal(t, expectedSanitized, *alert.RuleDescription, "FIX: RuleDescription is sanitized")
		assert.Equal(t, expectedSanitized, *alert.DismissedComment, "FIX: DismissedComment is sanitized")
		assert.Equal(t, expectedSanitized, *alert.Rule.Description, "FIX: Rule.Description is sanitized")
		assert.Equal(t, expectedSanitized, *alert.Rule.FullDescription, "FIX: Rule.FullDescription is sanitized")
		assert.Equal(t, expectedSanitized, *alert.Rule.Help, "FIX: Rule.Help is sanitized")
	})

	t.Run("ListCodeScanningAlerts - verify FIX", func(t *testing.T) {
		mockAlerts := []*github.Alert{mockAlert}
		mockClient := NewMockedHTTPClient(
			WithRequestMatchHandler(GetReposCodeScanningAlertsByOwnerByRepo, mockResponse(t, http.StatusOK, mockAlerts)),
		)
		client := github.NewClient(mockClient)
		deps := BaseDeps{Client: client}

		tool := ListCodeScanningAlerts(translations.NullTranslationHelper)
		handler := tool.Handler(deps)

		req := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		content := getTextResult(t, result)
		var alerts []*github.Alert
		err = json.Unmarshal([]byte(content.Text), &alerts)
		require.NoError(t, err)

		require.Len(t, alerts, 1)
		alert := alerts[0]

		// Asserting it IS sanitized
		assert.Equal(t, expectedSanitized, *alert.RuleDescription, "FIX: RuleDescription is sanitized")
		assert.Equal(t, expectedSanitized, *alert.Rule.Description, "FIX: Rule.Description is sanitized")
	})

	// This is what we WANT after the fix
	_ = expectedSanitized
}
