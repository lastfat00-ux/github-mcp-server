package github

import (
	"testing"

	"github.com/github/github-mcp-server/pkg/sanitize"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
)

func TestLabelsXSS(t *testing.T) {
	maliciousDesc := "<script>alert('xss')</script><b>Safe Label</b>"

	// Test direct sanitize usage on label description
	sanitized := sanitize.Sanitize(maliciousDesc)
	assert.NotContains(t, sanitized, "<script>")
	assert.NotContains(t, sanitized, "alert")
	assert.Equal(t, "<b>Safe Label</b>", sanitized)

	// Test fragmentToIssue label description sanitization
	var fragment IssueFragment
	fragment.Number = 1
	fragment.Title = "Test Issue"
	fragment.Body = "Test Body"
	fragment.Labels.Nodes = []struct {
		Name        githubv4.String
		ID          githubv4.String
		Description githubv4.String
	}{
		{
			Name:        "bug",
			ID:          "123",
			Description: githubv4.String(maliciousDesc),
		},
	}

	issue := fragmentToIssue(fragment)
	assert.Len(t, issue.Labels, 1)
	assert.NotContains(t, *issue.Labels[0].Description, "<script>")
	assert.NotContains(t, *issue.Labels[0].Description, "alert")
	assert.Equal(t, "<b>Safe Label</b>", *issue.Labels[0].Description)
}
