package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
)

func TestSecurityAdvisoriesSanitization(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	client := github.NewClient(nil)
	u, _ := url.Parse(server.URL + "/")
	client.BaseURL = u

	maliciousPayload := "Advisory with <script>alert('xss')</script> and <b>bold</b> text"
	expectedSanitized := "Advisory with  and <b>bold</b> text"

	t.Run("GetGlobalSecurityAdvisory sanitizes fields", func(t *testing.T) {
		mux.HandleFunc("/advisories/GHSA-1234", func(w http.ResponseWriter, r *http.Request) {
			advisory := &github.GlobalSecurityAdvisory{
				SecurityAdvisory: github.SecurityAdvisory{
					Summary:     github.Ptr(maliciousPayload),
					Description: github.Ptr(maliciousPayload),
				},
			}
			json.NewEncoder(w).Encode(advisory)
		})

		ctx := context.Background()
		deps := BaseDeps{Client: client}

		tool := GetGlobalSecurityAdvisory(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		request := createMCPRequest(map[string]any{"ghsaId": "GHSA-1234"})
		result, err := handler(ContextWithDeps(ctx, deps), &request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned github.GlobalSecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returned.Summary)
		assert.Equal(t, expectedSanitized, *returned.Description)
	})

	t.Run("ListGlobalSecurityAdvisories sanitizes fields", func(t *testing.T) {
		mux.HandleFunc("/advisories", func(w http.ResponseWriter, r *http.Request) {
			advisories := []*github.GlobalSecurityAdvisory{
				{
					SecurityAdvisory: github.SecurityAdvisory{
						Summary:     github.Ptr(maliciousPayload),
						Description: github.Ptr(maliciousPayload),
					},
				},
			}
			json.NewEncoder(w).Encode(advisories)
		})

		ctx := context.Background()
		deps := BaseDeps{Client: client}

		tool := ListGlobalSecurityAdvisories(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		request := createMCPRequest(map[string]any{})
		result, err := handler(ContextWithDeps(ctx, deps), &request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned []*github.GlobalSecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returned[0].Summary)
		assert.Equal(t, expectedSanitized, *returned[0].Description)
	})

	t.Run("ListRepositorySecurityAdvisories sanitizes fields", func(t *testing.T) {
		mux.HandleFunc("/repos/o/r/security-advisories", func(w http.ResponseWriter, r *http.Request) {
			advisories := []*github.SecurityAdvisory{
				{
					Summary:     github.Ptr(maliciousPayload),
					Description: github.Ptr(maliciousPayload),
				},
			}
			json.NewEncoder(w).Encode(advisories)
		})

		ctx := context.Background()
		deps := BaseDeps{Client: client}

		tool := ListRepositorySecurityAdvisories(translations.NullTranslationHelper)
		handler := tool.Handler(deps)
		request := createMCPRequest(map[string]any{"owner": "o", "repo": "r"})
		result, err := handler(ContextWithDeps(ctx, deps), &request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var returned []*github.SecurityAdvisory
		err = json.Unmarshal([]byte(textContent.Text), &returned)
		assert.NoError(t, err)
		assert.Equal(t, expectedSanitized, *returned[0].Summary)
		assert.Equal(t, expectedSanitized, *returned[0].Description)
	})
}
