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

func Test_SearchIssues_Sanitization(t *testing.T) {
	// This test verifies that search results are sanitized to prevent XSS.
	// We'll first check that it's currently NOT sanitized (or we'll just implement the fix and check it's sanitized).
	// Actually, the plan says "Verify that currently, the tool result contains the unsanitized HTML."

	maliciousTitle := "<script>alert('xss-title')</script>Safe Title"
	maliciousBody := "Safe Body<img src=x onerror=alert('xss-body')>"

	mockSearchResult := &github.IssuesSearchResult{
		Total: github.Ptr(1),
		Issues: []*github.Issue{
			{
				Number:  github.Ptr(1),
				Title:   github.Ptr(maliciousTitle),
				Body:    github.Ptr(maliciousBody),
				HTMLURL: github.Ptr("https://github.com/owner/repo/issues/1"),
				User: &github.User{
					Login: github.Ptr("attacker"),
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
		"query": "some query",
	})

	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)

	var returnedResult github.IssuesSearchResult
	err = json.Unmarshal([]byte(textContent.Text), &returnedResult)
	require.NoError(t, err)

	// After the fix, these assertions check for sanitized content.
	assert.NotContains(t, *returnedResult.Issues[0].Title, "<script>", "Title should not contain <script>")
	assert.NotContains(t, *returnedResult.Issues[0].Body, "onerror", "Body should not contain onerror")
	assert.Contains(t, *returnedResult.Issues[0].Title, "Safe Title")
	assert.Contains(t, *returnedResult.Issues[0].Body, "Safe Body")
}
