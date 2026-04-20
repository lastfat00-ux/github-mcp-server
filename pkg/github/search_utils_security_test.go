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

func Test_SearchIssues_Security(t *testing.T) {
	// Setup mock search results with XSS payloads
	maliciousTitle := "Exploit <script>alert('xss')</script>"
	maliciousBody := "Check this out: <img src=x onerror=alert('xss')> and <b>bold</b>"
	maliciousLabelName := "<svg/onload=alert(1)>"
	maliciousLabelDesc := "Dangerous label <iframe src='javascript:alert(1)'></iframe>"

	expectedSanitizedTitle := "Exploit "
	// Note: bluemonday.StrictPolicy() might strip more or less depending on exact configuration.
	// But it should definitely strip the script tag and the onerror attribute.
	// Actually pkg/sanitize uses a policy that allows some tags but strips others.

	mockSearchResult := &github.IssuesSearchResult{
		Total: github.Ptr(1),
		Issues: []*github.Issue{
			{
				ID:     github.Ptr(int64(12345)),
				Number: github.Ptr(1),
				Title:  github.Ptr(maliciousTitle),
				Body:   github.Ptr(maliciousBody),
				Labels: []*github.Label{
					{
						Name:        github.Ptr(maliciousLabelName),
						Description: github.Ptr(maliciousLabelDesc),
					},
				},
			},
		},
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetSearchIssues: mockResponse(t, http.StatusOK, mockSearchResult),
	})

	client := github.NewClient(mockedClient)
	serverTool := SearchIssues(translations.NullTranslationHelper)
	deps := BaseDeps{
		Client: client,
	}
	handler := serverTool.Handler(deps)

	request := createMCPRequest(map[string]interface{}{
		"query": "security test",
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)

	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)

	var returnedResult github.IssuesSearchResult
	err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
	require.NoError(t, err)

	require.Len(t, returnedResult.Issues, 1)
	issue := returnedResult.Issues[0]

	// Verify title is sanitized
	assert.NotContains(t, *issue.Title, "<script>")
	assert.Equal(t, expectedSanitizedTitle, *issue.Title)

	// Verify body is sanitized (some tags allowed, but malicious ones stripped)
	assert.NotContains(t, *issue.Body, "onerror")
	assert.Contains(t, *issue.Body, "<b>bold</b>")

	// Verify labels are sanitized
	require.Len(t, issue.Labels, 1)
	assert.NotContains(t, *issue.Labels[0].Name, "<svg")
	assert.NotContains(t, *issue.Labels[0].Description, "<iframe")
}
