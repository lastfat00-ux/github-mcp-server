package github

import (
	"testing"

	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
)

func Test_convertToMinimalProject_Sanitization(t *testing.T) {
	p := &github.ProjectV2{
		Title:            github.Ptr("<script>alert(1)</script>Title"),
		Description:      github.Ptr("<b>Description</b><img src=x onerror=alert(1)>"),
		ShortDescription: github.Ptr("<i>Short</i><iframe src=javascript:alert(1)></iframe>"),
	}
	m := convertToMinimalProject(p)
	assert.Equal(t, "Title", *m.Title)
	assert.Equal(t, "<b>Description</b><img src=\"x\">", *m.Description)
	assert.Equal(t, "<i>Short</i>", *m.ShortDescription)
}
