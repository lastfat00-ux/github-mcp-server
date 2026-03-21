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

func Test_Discussions_Sanitization(t *testing.T) {
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
				"title":      "Safe <script>alert('xss')</script>",
				"body":       "Safe body <img src=x onerror=alert(1)>",
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

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": int32(1)}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(getTextResult(t, res).Text), &out))

		assert.Equal(t, "Safe ", out["title"])
		assert.Equal(t, "Safe body <img src=\"x\">", out["body"])
	})

	t.Run("GetDiscussionComments sanitizes body", func(t *testing.T) {
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
							{"body": "Safe comment <script>console.log(1)</script>"},
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

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": int32(1)}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		var response struct {
			Comments []*github.IssueComment `json:"comments"`
		}
		require.NoError(t, json.Unmarshal([]byte(getTextResult(t, res).Text), &response))

		assert.Equal(t, "Safe comment ", *response.Comments[0].Body)
	})

	t.Run("ListDiscussions sanitizes title", func(t *testing.T) {
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
							"number":     1,
							"title":      "XSS <svg onload=alert(1)>",
							"createdAt":  "2023-01-01T00:00:00Z",
							"updatedAt":  "2023-01-01T00:00:00Z",
							"closed":     false,
							"isAnswered": false,
							"author":     map[string]any{"login": "user1"},
							"url":        "https://github.com/owner/repo/discussions/1",
							"category":   map[string]any{"name": "General"},
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

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo"}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)

		var response struct {
			Discussions []*github.Discussion `json:"discussions"`
		}
		require.NoError(t, json.Unmarshal([]byte(getTextResult(t, res).Text), &response))

		assert.Equal(t, "XSS ", *response.Discussions[0].Title)
	})
}
