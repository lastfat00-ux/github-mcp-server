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

func Test_DiscussionsSanitization(t *testing.T) {
	maliciousTitle := "Discussion with <script>alert('xss')</script>"
	maliciousBody := "Body with <img src=x onerror=alert('xss')>"
	maliciousComment := "Comment with <a href='javascript:alert(\"xss\")'>click me</a>"

	t.Run("list_discussions sanitization", func(t *testing.T) {
		toolDef := ListDiscussions(translations.NullTranslationHelper)

		qBasicNoOrder := "query($after:String$first:Int!$owner:String!$repo:String!){repository(owner: $owner, name: $repo){discussions(first: $first, after: $after){nodes{number,title,createdAt,updatedAt,closed,isAnswered,answerChosenAt,author{login},category{name},url},pageInfo{hasNextPage,hasPreviousPage,startCursor,endCursor},totalCount}}}"
		vars := map[string]interface{}{
			"owner": "owner",
			"repo":  "repo",
			"first": float64(30),
			"after": (*string)(nil),
		}

		mockResponse := githubv4mock.DataResponse(map[string]any{
			"repository": map[string]any{
				"discussions": map[string]any{
					"nodes": []map[string]any{
						{
							"number": 1,
							"title":  maliciousTitle,
							"url":    "https://github.com/owner/repo/discussions/1",
							"author": map[string]any{"login": "user1"},
							"category": map[string]any{"name": "General"},
							"createdAt": "2023-01-01T00:00:00Z",
							"updatedAt": "2023-01-01T00:00:00Z",
						},
					},
					"pageInfo": map[string]any{
						"hasNextPage":     false,
						"hasPreviousPage": false,
						"startCursor":     "",
						"endCursor":       "",
					},
					"totalCount": 1,
				},
			},
		})

		matcher := githubv4mock.NewQueryMatcher(qBasicNoOrder, vars, mockResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)
		deps := BaseDeps{GQLClient: gqlClient}
		handler := toolDef.Handler(deps)

		req := createMCPRequest(map[string]interface{}{"owner": "owner", "repo": "repo"})
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var response struct {
			Discussions []*github.Discussion `json:"discussions"`
		}
		require.NoError(t, json.Unmarshal([]byte(text), &response))

		assert.NotContains(t, *response.Discussions[0].Title, "<script>", "Title should be sanitized")
	})

	t.Run("get_discussion sanitization", func(t *testing.T) {
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
				"title":      maliciousTitle,
				"body":       maliciousBody,
				"url":        "https://github.com/owner/repo/discussions/1",
				"createdAt":  "2023-01-01T00:00:00Z",
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

		req := createMCPRequest(map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": 1})
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var response map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(text), &response))

		assert.NotContains(t, response["title"], "<script>", "Title should be sanitized")
		assert.NotContains(t, response["body"], "onerror", "Body should be sanitized")
		assert.Contains(t, response["body"], "<img", "Safe img tag should be allowed")
	})

	t.Run("get_discussion_comments sanitization", func(t *testing.T) {
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
							{"body": maliciousComment},
						},
						"pageInfo": map[string]any{
							"hasNextPage":     false,
							"hasPreviousPage": false,
							"startCursor":     "",
							"endCursor":       "",
						},
						"totalCount": 1,
					},
				},
			},
		})

		matcher := githubv4mock.NewQueryMatcher(qGetComments, vars, mockResponse)
		httpClient := githubv4mock.NewMockedHTTPClient(matcher)
		gqlClient := githubv4.NewClient(httpClient)
		deps := BaseDeps{GQLClient: gqlClient}
		handler := toolDef.Handler(deps)

		req := createMCPRequest(map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": 1})
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		text := getTextResult(t, res).Text
		var response struct {
			Comments []*github.IssueComment `json:"comments"`
		}
		require.NoError(t, json.Unmarshal([]byte(text), &response))

		assert.NotContains(t, *response.Comments[0].Body, "javascript:", "Comment body should be sanitized")
	})
}
