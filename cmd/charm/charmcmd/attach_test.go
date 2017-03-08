// Copyright 2015 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd_test

import (
	"crypto/sha512"
	"io/ioutil"
	"path/filepath"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/charm.v6-unstable"
	"gopkg.in/juju/charmrepo.v2-unstable/csclient/params"
	charmtesting "gopkg.in/juju/charmrepo.v2-unstable/testing"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
)

type attachSuite struct {
	commonSuite
}

var _ = gc.Suite(&attachSuite{})

func (s *attachSuite) SetUpTest(c *gc.C) {
	s.commonSuite.SetUpTest(c)
	s.discharge = func(cavId, cav string) ([]checkers.Caveat, error) {
		return []checkers.Caveat{
			checkers.DeclaredCaveat("username", "bob"),
		}, nil
	}
}

var attachInitErrorTests = []struct {
	args []string
	err  string
}{{
	err: "no charm id specified",
}, {
	args: []string{"wordpress"},
	err:  "no resource specified",
}, {
	args: []string{"wordpress", "foo"},
	err:  "expected name=path format for resource",
}, {
	args: []string{"wordpress", "=foo"},
	err:  "missing resource name",
}, {
	args: []string{"invalid:entity", "foo=bar"},
	err:  `invalid charm id: cannot parse URL "invalid:entity": schema "invalid" not valid`,
}, {
	args: []string{"wordpress", "foo", "something else"},
	err:  "too many arguments",
}}

func (s *attachSuite) TestInitError(c *gc.C) {
	dir := c.MkDir()
	for i, test := range attachInitErrorTests {
		c.Logf("test %d: %q", i, test.args)
		args := []string{"attach"}
		stdout, stderr, code := run(dir, append(args, test.args...)...)
		c.Assert(stdout, gc.Equals, "")
		c.Assert(stderr, gc.Matches, "error: "+test.err+"\n")
		c.Assert(code, gc.Equals, 2)
	}
}

func (s *attachSuite) TestRun(c *gc.C) {
	ch := charmtesting.NewCharmMeta(charmtesting.MetaWithResources(nil, "someResource"))
	id := charm.MustParseURL("~bob/precise/wordpress")
	id, err := s.client.UploadCharm(id, ch)
	c.Assert(err, gc.IsNil)

	dir := c.MkDir()
	err = ioutil.WriteFile(filepath.Join(dir, "bar.zip"), []byte("content"), 0666)
	c.Assert(err, gc.IsNil)

	stdout, stderr, exitCode := run(dir, "attach", "--channel=unpublished", "~bob/precise/wordpress", "someResource=bar.zip")
	c.Check(stdout, gc.Matches, `((\r.*)+\n)?uploaded revision 0 of someResource\n`)
	c.Check(stderr, gc.Equals, "")
	c.Assert(exitCode, gc.Equals, 0)

	// Check that the resource has actually been attached.
	resources, err := s.client.WithChannel("unpublished").ListResources(id)
	c.Assert(err, gc.IsNil)
	c.Assert(resources, jc.DeepEquals, []params.Resource{{
		Name:        "someResource",
		Type:        "file",
		Path:        "someResource-file",
		Revision:    0,
		Fingerprint: hashOfString("content"),
		Size:        int64(len("content")),
		Description: "someResource description",
	}})
}

func (s *attachSuite) TestRunFailsWithoutRevisionOnStableChannel(c *gc.C) {
	dir := c.MkDir()
	err := ioutil.WriteFile(filepath.Join(dir, "bar.zip"), []byte("content"), 0666)
	c.Assert(err, gc.IsNil)
	stdout, stderr, exitCode := run(dir, "attach", "--channel=stable", "~bob/precise/wordpress", "someResource=bar.zip")
	c.Assert(exitCode, gc.Equals, 1)
	c.Check(stderr, gc.Matches, "ERROR A revision is required when attaching to a charm in the stable channel.\n")
	c.Check(stdout, gc.Matches, "")

}

func hashOfString(s string) []byte {
	x := sha512.Sum384([]byte(s))
	return x[:]
}

func (s *attachSuite) TestCannotOpenFile(c *gc.C) {
	path := filepath.Join(c.MkDir(), "/not-there")
	stdout, stderr, exitCode := run(c.MkDir(), "attach", "wordpress-0", "foo="+path)
	c.Assert(exitCode, gc.Equals, 1)
	c.Assert(stdout, gc.Equals, "")
	c.Assert(stderr, gc.Matches, `ERROR open .*not-there: no such file or directory`+"\n")
}
