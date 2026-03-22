package github

import (
	"testing"

	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
)

func Test_fragmentToDiscussion_Sanitization(t *testing.T) {
	fragment := NodeFragment{
		Number: githubv4.Int(1),
		Title:  githubv4.String("Exploit <script>alert('xss')</script>"),
		Author: struct{ Login githubv4.String }{Login: githubv4.String("user")},
		Category: struct{ Name githubv4.String }{Name: githubv4.String("category")},
		URL: githubv4.String("https://github.com/owner/repo/discussions/1"),
	}

	discussion := fragmentToDiscussion(fragment)
	assert.Equal(t, "Exploit ", *discussion.Title, "Discussion title should be sanitized")
}
