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

func TestDiscussionsSecurity(t *testing.T) {
	maliciousTitle := "Discussion with <script>alert('xss')</script> in title"
	maliciousBody := "Discussion with <img src=x onerror=alert('xss')> in body"
	maliciousComment := "Comment with <iframe src='javascript:alert(1)'></iframe>"

	sanitizedTitle := "Discussion with  in title"
	sanitizedBody := "Discussion with <img src=\"x\"> in body"
	sanitizedComment := "Comment with "

	t.Run("GetDiscussion sanitization", func(t *testing.T) {
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

		toolDef := GetDiscussion(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		reqParams := map[string]interface{}{"owner": "owner", "repo": "repo", "discussionNumber": int32(1)}
		req := createMCPRequest(reqParams)
		res, err := handler(ContextWithDeps(context.Background(), deps), &req)
		require.NoError(t, err)
		require.False(t, res.IsError)

		text := getTextResult(t, res).Text
		var out map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(text), &out))

		assert.Equal(t, sanitizedTitle, out["title"])
		assert.Equal(t, sanitizedBody, out["body"])
		assert.NotContains(t, out["title"], "<script>")
		assert.NotContains(t, out["body"], "onerror")
	})

	t.Run("GetDiscussionComments sanitization", func(t *testing.T) {
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

		toolDef := GetDiscussionComments(translations.NullTranslationHelper)
		handler := toolDef.Handler(deps)

		reqParams := map[string]interface{}{
			"owner":            "owner",
			"repo":             "repo",
			"discussionNumber": int32(1),
		}
		request := createMCPRequest(reqParams)

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		text := getTextResult(t, result).Text
		var response struct {
			Comments []struct {
				Body string `json:"body"`
			} `json:"comments"`
		}
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		require.Len(t, response.Comments, 1)
		assert.Equal(t, sanitizedComment, response.Comments[0].Body)
		assert.NotContains(t, response.Comments[0].Body, "iframe")
	})
}
