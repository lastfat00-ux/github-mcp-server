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

func TestActionsXSSSanitization(t *testing.T) {
	maliciousTitle := "Malicious <script>alert('xss')</script> Title"
	sanitizedTitle := "Malicious  Title"

	t.Run("ListWorkflows sanitization", func(t *testing.T) {
		toolDef := ListWorkflows(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsWorkflowsByOwnerByRepo: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				workflows := &github.Workflows{
					TotalCount: github.Ptr(1),
					Workflows: []*github.Workflow{
						{
							Name: github.Ptr(maliciousTitle),
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
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo"})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)
		require.False(t, result.IsError)

		var response github.Workflows
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)
		assert.Equal(t, sanitizedTitle, *response.Workflows[0].Name)
	})

	t.Run("ListWorkflowRuns sanitization", func(t *testing.T) {
		toolDef := ListWorkflowRuns(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsWorkflowsRunsByOwnerByRepoByWorkflowID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				runs := &github.WorkflowRuns{
					TotalCount: github.Ptr(1),
					WorkflowRuns: []*github.WorkflowRun{
						{
							Name:         github.Ptr(maliciousTitle),
							DisplayTitle: github.Ptr(maliciousTitle),
							HeadBranch:   github.Ptr(maliciousTitle),
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(runs)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo", "workflow_id": "ci.yml"})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		var response github.WorkflowRuns
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)
		assert.Equal(t, sanitizedTitle, *response.WorkflowRuns[0].Name)
		assert.Equal(t, sanitizedTitle, *response.WorkflowRuns[0].DisplayTitle)
		assert.Equal(t, sanitizedTitle, *response.WorkflowRuns[0].HeadBranch)
	})

	t.Run("ListWorkflowJobs sanitization", func(t *testing.T) {
		toolDef := ListWorkflowJobs(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsRunsJobsByOwnerByRepoByRunID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				jobs := &github.Jobs{
					TotalCount: github.Ptr(1),
					Jobs: []*github.WorkflowJob{
						{
							Name:         github.Ptr(maliciousTitle),
							HeadBranch:   github.Ptr(maliciousTitle),
							WorkflowName: github.Ptr(maliciousTitle),
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
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo", "run_id": 123.0})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		var response map[string]any
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)

		jobs := response["jobs"].(map[string]any)["jobs"].([]any)
		job := jobs[0].(map[string]any)
		assert.Equal(t, sanitizedTitle, job["name"])
		assert.Equal(t, sanitizedTitle, job["head_branch"])
		assert.Equal(t, sanitizedTitle, job["workflow_name"])
	})

	t.Run("GetJobLogs failed jobs sanitization", func(t *testing.T) {
		toolDef := GetJobLogs(translations.NullTranslationHelper)
		mockedClient := MockHTTPClientWithHandlers(map[string]http.HandlerFunc{
			GetReposActionsRunsJobsByOwnerByRepoByRunID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				jobs := &github.Jobs{
					TotalCount: github.Ptr(1),
					Jobs: []*github.WorkflowJob{
						{
							ID:         github.Ptr(int64(1)),
							Name:       github.Ptr(maliciousTitle),
							Conclusion: github.Ptr("failure"),
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(jobs)
			}),
			GetReposActionsJobsLogsByOwnerByRepoByJobID: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://github.com/logs/job/1")
				w.WriteHeader(http.StatusFound)
			}),
		})

		client := github.NewClient(mockedClient)
		deps := BaseDeps{Client: client}
		handler := toolDef.Handler(deps)
		request := createMCPRequest(map[string]any{"owner": "owner", "repo": "repo", "run_id": 123.0, "failed_only": true})

		result, err := handler(ContextWithDeps(context.Background(), deps), &request)
		require.NoError(t, err)

		var response map[string]any
		err = json.Unmarshal([]byte(getTextResult(t, result).Text), &response)
		require.NoError(t, err)

		logs := response["logs"].([]any)
		log := logs[0].(map[string]any)
		assert.Equal(t, sanitizedTitle, log["job_name"])
	})
}
