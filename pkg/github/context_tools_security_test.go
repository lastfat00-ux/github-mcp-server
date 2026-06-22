package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetMe_Security(t *testing.T) {
	t.Parallel()

	serverTool := GetMe(translations.NullTranslationHelper)

	maliciousPayload := "Test<script>alert('XSS')</script><b>Safe</b>"
	expectedSanitized := "Test<b>Safe</b>"

	mockUser := &github.User{
		Login:           github.Ptr("testuser"),
		Name:            github.Ptr(maliciousPayload),
		Company:         github.Ptr(maliciousPayload),
		Blog:            github.Ptr(maliciousPayload),
		Location:        github.Ptr(maliciousPayload),
		Email:           github.Ptr(maliciousPayload),
		Bio:             github.Ptr(maliciousPayload),
		TwitterUsername: github.Ptr(maliciousPayload),
	}

	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetUser: mockResponse(t, http.StatusOK, mockUser),
	})

	deps := BaseDeps{Client: github.NewClient(mockedClient)}
	handler := serverTool.Handler(deps)

	request := createMCPRequest(map[string]any{})
	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var returnedUser MinimalUser
	err = json.Unmarshal([]byte(textContent.Text), &returnedUser)
	require.NoError(t, err)

	assert.Equal(t, expectedSanitized, returnedUser.Details.Name)
	assert.Equal(t, expectedSanitized, returnedUser.Details.Company)
	assert.Equal(t, expectedSanitized, returnedUser.Details.Location)
	assert.Equal(t, expectedSanitized, returnedUser.Details.Bio)

	// These are intentionally not sanitized in implementation to preserve data integrity (URLs/Emails)
	assert.Equal(t, maliciousPayload, returnedUser.Details.Blog)
	assert.Equal(t, maliciousPayload, returnedUser.Details.Email)
	assert.Equal(t, maliciousPayload, returnedUser.Details.TwitterUsername)
}

func Test_GetTeams_Security(t *testing.T) {
	t.Parallel()

	serverTool := GetTeams(translations.NullTranslationHelper)

	maliciousPayload := "Team<script>alert('XSS')</script><b>Safe</b>"
	expectedSanitized := "Team<b>Safe</b>"

	mockTeamsResponse := githubv4mock.DataResponse(map[string]any{
		"user": map[string]any{
			"organizations": map[string]any{
				"nodes": []map[string]any{
					{
						"login": "testorg",
						"teams": map[string]any{
							"nodes": []map[string]any{
								{
									"name":        maliciousPayload,
									"slug":        "team-slug",
									"description": maliciousPayload,
								},
							},
						},
					},
				},
			},
		},
	})

	queryStr := "query($login:String!){user(login: $login){organizations(first: 100){nodes{login,teams(first: 100, userLogins: [$login]){nodes{name,slug,description}}}}}}"
	vars := map[string]interface{}{
		"login": "testuser",
	}
	matcher := githubv4mock.NewQueryMatcher(queryStr, vars, mockTeamsResponse)
	httpClient := githubv4mock.NewMockedHTTPClient(matcher)
	gqlClient := githubv4.NewClient(httpClient)

	mockUser := &github.User{Login: github.Ptr("testuser")}
	mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
		GetUser: mockResponse(t, http.StatusOK, mockUser),
	})

	deps := BaseDeps{
		Client:    github.NewClient(mockedClient),
		GQLClient: gqlClient,
	}
	handler := serverTool.Handler(deps)

	request := createMCPRequest(map[string]any{})
	result, err := handler(ContextWithDeps(context.Background(), deps), &request)
	require.NoError(t, err)
	require.False(t, result.IsError)

	textContent := getTextResult(t, result)
	var organizations []OrganizationTeams
	err = json.Unmarshal([]byte(textContent.Text), &organizations)
	require.NoError(t, err)

	require.Len(t, organizations, 1)
	require.Len(t, organizations[0].Teams, 1)
	assert.Equal(t, expectedSanitized, organizations[0].Teams[0].Name)
	assert.Equal(t, expectedSanitized, organizations[0].Teams[0].Description)
}
