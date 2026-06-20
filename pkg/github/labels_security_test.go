package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LabelsSecurity(t *testing.T) {
	t.Parallel()

	maliciousDescription := "Label with <script>alert('xss')</script><b>safe</b>"
	expectedDescription := "Label with <b>safe</b>"

	mockLabelResponse := githubv4mock.DataResponse(map[string]any{
		"repository": map[string]any{
			"label": map[string]any{
				"id":          "label-1",
				"name":        "security-risk",
				"color":       "ff0000",
				"description": maliciousDescription,
			},
		},
	})

	mockListLabelsResponse := githubv4mock.DataResponse(map[string]any{
		"repository": map[string]any{
			"labels": map[string]any{
				"nodes": []map[string]any{
					{
						"id":          "label-1",
						"name":        "security-risk",
						"color":       "ff0000",
						"description": maliciousDescription,
					},
				},
				"totalCount": 1,
			},
		},
	})

	t.Run("GetLabel sanitizes description", func(t *testing.T) {
		queryStr := "query($name:String!$owner:String!$repo:String!){repository(owner: $owner, name: $repo){label(name: $name){id,name,color,description}}}"
		vars := map[string]interface{}{
			"owner": "test-owner",
			"repo":  "test-repo",
			"name":  "security-risk",
		}
		matcher := githubv4mock.NewQueryMatcher(queryStr, vars, mockLabelResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)

		deps := BaseDeps{GQLClient: gqlClient}
		serverTool := GetLabel(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "test-owner",
			"repo":  "test-repo",
			"name":  "security-risk",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var label map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &label)
		require.NoError(t, err)

		assert.Equal(t, expectedDescription, label["description"])
	})

	t.Run("ListLabels sanitizes description", func(t *testing.T) {
		queryStr := "query($owner:String!$repo:String!){repository(owner: $owner, name: $repo){labels(first: 100){nodes{id,name,color,description},totalCount}}}"
		vars := map[string]interface{}{
			"owner": "test-owner",
			"repo":  "test-repo",
		}
		matcher := githubv4mock.NewQueryMatcher(queryStr, vars, mockListLabelsResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)

		deps := BaseDeps{GQLClient: gqlClient}
		serverTool := ListLabels(translations.NullTranslationHelper)
		handler := serverTool.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "test-owner",
			"repo":  "test-repo",
		})
		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		labels := response["labels"].([]any)
		assert.Len(t, labels, 1)
		label := labels[0].(map[string]any)
		assert.Equal(t, expectedDescription, label["description"])
	})
}
