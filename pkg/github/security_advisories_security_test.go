package github

import (
	"testing"

	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
)

func TestSecurityAdvisorySanitization(t *testing.T) {
	payload := "Hello <script>alert('xss')</script><img src=x onerror=alert(1)> world"
	expected := "Hello <img src=\"x\"> world"

	advisory := &github.SecurityAdvisory{
		Summary:     github.Ptr(payload),
		Description: github.Ptr(payload),
	}

	sanitizeSecurityAdvisory(advisory)

	assert.Equal(t, expected, *advisory.Summary)
	assert.Equal(t, expected, *advisory.Description)

	globalAdvisory := &github.GlobalSecurityAdvisory{
		SecurityAdvisory: github.SecurityAdvisory{
			Summary:     github.Ptr(payload),
			Description: github.Ptr(payload),
		},
	}

	sanitizeGlobalSecurityAdvisory(globalAdvisory)

	assert.Equal(t, expected, *globalAdvisory.Summary)
	assert.Equal(t, expected, *globalAdvisory.Description)
}
