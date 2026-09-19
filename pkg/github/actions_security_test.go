package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ActionsXSS(t *testing.T) {
	t.Run("ListWorkflows sanitizes workflow names", func(t *testing.T) {
		toolDef := ListWorkflows(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsWorkflowsByOwnerByRepo: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				workflows := &github.Workflows{
					TotalCount: github.Ptr(1),
					Workflows: []*github.Workflow{
						{
							ID:   github.Ptr(int64(123)),
							Name: github.Ptr("CI <script>alert('xss')</script><b>safe</b>"),
							Path: github.Ptr(".github/workflows/ci.yml"),
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(workflows)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner": "owner",
			"repo":  "repo",
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response github.Workflows
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		require.Len(t, response.Workflows, 1)
		assert.NotContains(t, *response.Workflows[0].Name, "<script>")
		assert.Equal(t, "CI <b>safe</b>", *response.Workflows[0].Name)
	})

	t.Run("GetWorkflowRun sanitizes display title and commit message", func(t *testing.T) {
		toolDef := GetWorkflowRun(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsRunsByOwnerByRepoByRunID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				run := &github.WorkflowRun{
					ID:           github.Ptr(int64(12345)),
					Name:         github.Ptr("Build <iframe src=javascript:alert(1)></iframe>"),
					DisplayTitle: github.Ptr("Commit title <img src=x onerror=alert(1)>"),
					HeadCommit: &github.HeadCommit{
						Message: github.Ptr("Fix bug <script>evil()</script>"),
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(run)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner":  "owner",
			"repo":   "repo",
			"run_id": float64(12345),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response github.WorkflowRun
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		assert.NotContains(t, *response.Name, "<iframe>")
		assert.NotContains(t, *response.DisplayTitle, "onerror")
		assert.NotContains(t, *response.HeadCommit.Message, "<script>")
	})

	t.Run("ListWorkflowJobs sanitizes job names and step names", func(t *testing.T) {
		toolDef := ListWorkflowJobs(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsRunsJobsByOwnerByRepoByRunID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				jobs := &github.Jobs{
					TotalCount: github.Ptr(1),
					Jobs: []*github.WorkflowJob{
						{
							ID:           github.Ptr(int64(1)),
							Name:         github.Ptr("Job <script>alert(1)</script>"),
							WorkflowName: github.Ptr("Workflow <svg onload=alert(1)>"),
							Steps: []*github.TaskStep{
								{
									Name: github.Ptr("Step <script>bad()</script>"),
								},
							},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(jobs)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)

		request := createMCPRequest(map[string]any{
			"owner":  "owner",
			"repo":   "repo",
			"run_id": float64(12345),
		})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		textContent := getTextResult(t, result)
		var response map[string]any
		err = json.Unmarshal([]byte(textContent.Text), &response)
		require.NoError(t, err)

		jobsRaw, ok := response["jobs"].(map[string]any)
		require.True(t, ok)
		jobsList, ok := jobsRaw["jobs"].([]any)
		require.True(t, ok)
		require.Len(t, jobsList, 1)

		jobMap := jobsList[0].(map[string]any)
		assert.NotContains(t, jobMap["name"], "<script>")
		assert.NotContains(t, jobMap["workflow_name"], "<svg")

		steps := jobMap["steps"].([]any)
		stepMap := steps[0].(map[string]any)
		assert.NotContains(t, stepMap["name"], "<script>")
	})
}
