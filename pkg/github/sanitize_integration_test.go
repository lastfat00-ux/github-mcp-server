package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizationIntegration(t *testing.T) {
	ctx := context.Background()
	t.Run("GetDiscussion sanitizes title and body", func(t *testing.T) {
		toolDef := GetDiscussion(translations.NullTranslationHelper)

		qGetDiscussion := "query($discussionNumber:Int!$owner:String!$repo:String!){repository(owner: $owner, name: $repo){discussion(number: $discussionNumber){number,title,body,createdAt,closed,isAnswered,answerChosenAt,url,category{name}}}}"
		vars := map[string]interface{}{
			"owner":            "owner",
			"repo":             "repo",
			"discussionNumber": float64(1),
		}

		mockResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{"discussion": map[string]any{
				"number":     1,
				"title":      "Test <script>alert('xss')</script> Title",
				"body":       "This is a test discussion with <b>bold</b> and <iframe src='javascript:alert(1)'></iframe>",
				"url":        "https://github.com/owner/repo/discussions/1",
				"createdAt":  "2025-04-25T12:00:00Z",
				"closed":     false,
				"isAnswered": false,
				"category":   map[string]any{"name": "General"},
			}},
		})

		matcher := githubv4mock.NewQueryMatcher(qGetDiscussion, vars, mockResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)
		deps := BaseDeps{GQLClient: gqlClient}
		handler := toolDef.Handler(deps)

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": 1}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(ctx, deps), &req)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var out map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(text), &out))

		assert.Equal(t, "Test  Title", out["title"])
		assert.Equal(t, "This is a test discussion with <b>bold</b> and ", out["body"])
	})

	t.Run("GetDiscussionComments sanitizes comment body", func(t *testing.T) {
		toolDef := GetDiscussionComments(translations.NullTranslationHelper)

		qGetComments := "query($after:String$discussionNumber:Int!$first:Int!$owner:String!$repo:String!){repository(owner: $owner, name: $repo){discussion(number: $discussionNumber){comments(first: $first, after: $after){nodes{body},pageInfo{hasNextPage,hasPreviousPage,startCursor,endCursor},totalCount}}}}"
		vars := map[string]interface{}{
			"owner":            "owner",
			"repo":             "repo",
			"discussionNumber": float64(1),
			"first":            float64(30),
			"after":            (*string)(nil),
		}

		mockResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{
				"discussion": map[string]any{
					"comments": map[string]any{
						"nodes": []map[string]any{
							{"body": "Safe comment"},
							{"body": "Unsafe <script>alert(1)</script> comment"},
						},
						"pageInfo": map[string]any{
							"hasNextPage":     false,
							"hasPreviousPage": false,
							"startCursor":     "",
							"endCursor":       "",
						},
						"totalCount": 2,
					},
				},
			},
		})

		matcher := githubv4mock.NewQueryMatcher(qGetComments, vars, mockResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)
		deps := BaseDeps{GQLClient: gqlClient}
		handler := toolDef.Handler(deps)

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": 1}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(ctx, deps), &req)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var response struct {
			Comments []*github.IssueComment `json:"comments"`
		}
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		require.Len(t, response.Comments, 2)
		assert.Equal(t, "Safe comment", *response.Comments[0].Body)
		assert.Equal(t, "Unsafe  comment", *response.Comments[1].Body)
	})
}
