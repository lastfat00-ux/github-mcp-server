package github

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/github/github-mcp-server/internal/githubv4mock"
	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LabelsSecurity_XSS(t *testing.T) {
	maliciousDescription := "Label description <script>alert('XSS')</script>"
	expectedDescription := "Label description "

	tests := []struct {
		name        string
		tool        func(translations.TranslationHelperFunc) inventory.ServerTool
		requestArgs map[string]any
		mockData    map[string]any
		query       any
		vars        map[string]any
		isMutation  bool
	}{
		{
			name: "get_label sanitization",
			tool: GetLabel,
			requestArgs: map[string]any{
				"owner": "owner",
				"repo":  "repo",
				"name":  "bug",
			},
			mockData: map[string]any{
				"repository": map[string]any{
					"label": map[string]any{
						"id":          githubv4.ID("label-1"),
						"name":        githubv4.String("bug"),
						"color":       githubv4.String("d73a4a"),
						"description": githubv4.String(maliciousDescription),
					},
				},
			},
			query: struct {
				Repository struct {
					Label struct {
						ID          githubv4.ID
						Name        githubv4.String
						Color       githubv4.String
						Description githubv4.String
					} `graphql:"label(name: $name)"`
				} `graphql:"repository(owner: $owner, name: $repo)"`
			}{},
			vars: map[string]any{
				"owner": githubv4.String("owner"),
				"repo":  githubv4.String("repo"),
				"name":  githubv4.String("bug"),
			},
		},
		{
			name: "list_label sanitization",
			tool: ListLabels,
			requestArgs: map[string]any{
				"owner": "owner",
				"repo":  "repo",
			},
			mockData: map[string]any{
				"repository": map[string]any{
					"labels": map[string]any{
						"nodes": []any{
							map[string]any{
								"id":          githubv4.ID("label-1"),
								"name":        githubv4.String("bug"),
								"color":       githubv4.String("d73a4a"),
								"description": githubv4.String(maliciousDescription),
							},
						},
						"totalCount": githubv4.Int(1),
					},
				},
			},
			query: struct {
				Repository struct {
					Labels struct {
						Nodes []struct {
							ID          githubv4.ID
							Name        githubv4.String
							Color       githubv4.String
							Description githubv4.String
						}
						TotalCount githubv4.Int
					} `graphql:"labels(first: 100)"`
				} `graphql:"repository(owner: $owner, name: $repo)"`
			}{},
			vars: map[string]any{
				"owner": githubv4.String("owner"),
				"repo":  githubv4.String("repo"),
			},
		},
		{
			name: "issue_read get_labels sanitization",
			tool: IssueRead,
			requestArgs: map[string]any{
				"method":       "get_labels",
				"owner":        "owner",
				"repo":         "repo",
				"issue_number": float64(123),
			},
			mockData: map[string]any{
				"repository": map[string]any{
					"issue": map[string]any{
						"labels": map[string]any{
							"nodes": []any{
								map[string]any{
									"id":          githubv4.ID("label-1"),
									"name":        githubv4.String("bug"),
									"color":       githubv4.String("d73a4a"),
									"description": githubv4.String(maliciousDescription),
								},
							},
							"totalCount": githubv4.Int(1),
						},
					},
				},
			},
			query: struct {
				Repository struct {
					Issue struct {
						Labels struct {
							Nodes []struct {
								ID          githubv4.ID
								Name        githubv4.String
								Color       githubv4.String
								Description githubv4.String
							}
							TotalCount githubv4.Int
						} `graphql:"labels(first: 100)"`
					} `graphql:"issue(number: $issueNumber)"`
				} `graphql:"repository(owner: $owner, name: $repo)"`
			}{},
			vars: map[string]any{
				"owner":       githubv4.String("owner"),
				"repo":        githubv4.String("repo"),
				"issueNumber": githubv4.Int(123),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTPClient := githubv4mock.NewMockedHTTPClient(
				githubv4mock.NewQueryMatcher(
					tc.query,
					tc.vars,
					githubv4mock.DataResponse(tc.mockData),
				),
			)

			gqlClient := githubv4.NewClient(mockHTTPClient)
			client := github.NewClient(nil)
			deps := BaseDeps{
				Client:    client,
				GQLClient: gqlClient,
			}
			serverTool := tc.tool(translations.NullTranslationHelper)
			handler := serverTool.Handler(deps)

			request := createMCPRequest(tc.requestArgs)
			result, err := handler(ContextWithDeps(context.Background(), deps), &request)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			textContent := getTextResult(t, result)

			if tc.name == "list_label sanitization" || tc.name == "issue_read get_labels sanitization" {
				var response struct {
					Labels []map[string]any `json:"labels"`
				}
				err = json.Unmarshal([]byte(textContent.Text), &response)
				require.NoError(t, err)
				assert.Equal(t, expectedDescription, response.Labels[0]["description"])
			} else {
				var response map[string]any
				err = json.Unmarshal([]byte(textContent.Text), &response)
				require.NoError(t, err)
				assert.Equal(t, expectedDescription, response["description"])
			}
		})
	}
}

func Test_ListIssues_LabelsSecurity_XSS(t *testing.T) {
	maliciousDescription := "Label description <script>alert('XSS')</script>"
	expectedDescription := "Label description "

	mockIssue := map[string]any{
		"number":     123,
		"title":      "Test Issue",
		"body":       "Test Body",
		"state":      "OPEN",
		"databaseId": 1001,
		"createdAt":  "2023-01-01T00:00:00Z",
		"updatedAt":  "2023-01-01T00:00:00Z",
		"author":     map[string]any{"login": "user1"},
		"labels": map[string]any{
			"nodes": []map[string]any{
				{"name": "bug", "id": "label1", "description": maliciousDescription},
			},
		},
		"comments": map[string]any{
			"totalCount": 0,
		},
	}

	mockResponse := githubv4mock.DataResponse(map[string]any{
		"repository": map[string]any{
			"issues": map[string]any{
				"nodes": []any{mockIssue},
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

	vars := map[string]interface{}{
		"owner":     "owner",
		"repo":      "repo",
		"states":    []interface{}{"OPEN", "CLOSED"},
		"orderBy":   "CREATED_AT",
		"direction": "DESC",
		"first":     float64(30),
		"after":     (*string)(nil),
	}

	q := "query($after:String$direction:OrderDirection!$first:Int!$orderBy:IssueOrderField!$owner:String!$repo:String!$states:[IssueState!]!){repository(owner: $owner, name: $repo){issues(first: $first, after: $after, states: $states, orderBy: {field: $orderBy, direction: $direction}){nodes{number,title,body,state,databaseId,author{login},createdAt,updatedAt,labels(first: 100){nodes{name,id,description}},comments{totalCount}},pageInfo{hasNextPage,hasPreviousPage,startCursor,endCursor},totalCount}}}"

	mockHTTPClient := githubv4mock.NewMockedHTTPClient(
		githubv4mock.NewQueryMatcher(q, vars, mockResponse),
	)

	gqlClient := githubv4.NewClient(mockHTTPClient)
	deps := BaseDeps{
		GQLClient: gqlClient,
	}
	serverTool := ListIssues(translations.NullTranslationHelper)
	handler := serverTool.Handler(deps)

	request := createMCPRequest(map[string]any{
		"owner": "owner",
		"repo":  "repo",
	})
	result, err := handler(ContextWithDeps(context.Background(), deps), &request)

	require.NoError(t, err)
	require.NotNil(t, result)

	textContent := getTextResult(t, result)
	var response struct {
		Issues []*github.Issue `json:"issues"`
	}
	err = json.Unmarshal([]byte(textContent.Text), &response)
	require.NoError(t, err)

	assert.Equal(t, expectedDescription, *response.Issues[0].Labels[0].Description)
}
