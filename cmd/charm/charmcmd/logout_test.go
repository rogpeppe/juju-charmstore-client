// Copyright 2015 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd_test

import (
	"net/url"
	"os"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/persistent-cookiejar"
	"golang.org/x/net/publicsuffix"
)

type logoutSuite struct {
	*charmstoreEnv
}

func (s *logoutSuite) Init(c *qt.C) {
	fakeHome(c)
	s.charmstoreEnv = initCharmstoreEnv(c)
}

func TestLogout(t *testing.T) {
	RunSuite(qt.New(t), &logoutSuite{})
}

func (s *logoutSuite) TestNotLoggedIn(c *qt.C) {
	s.discharger.SetDefaultUser("test-user")
	stdout, stderr, code := run(c.Mkdir(), "logout")
	c.Assert(stdout, qt.Equals, "")
	c.Assert(stderr, qt.Matches, "")
	c.Assert(code, qt.Equals, 0)
	s.checkNoUser(c)
}

func (s *logoutSuite) TestWithCookie(c *qt.C) {
	s.discharger.SetDefaultUser("test-user")
	dir := c.Mkdir()
	_, stderr, code := run(dir, "login")
	c.Assert(code, qt.Equals, 0, qt.Commentf("stderr: %s", stderr))
	c.Assert(isNonEmptyFile(s.cookieFile), qt.Equals, true)

	stdout, stderr, code := run(dir, "logout")
	c.Assert(stdout, qt.Equals, "")
	c.Assert(stderr, qt.Matches, "")
	c.Assert(code, qt.Equals, 0)
	s.checkNoUser(c)
}

func (s *logoutSuite) checkNoUser(c *qt.C) {
	s.discharger.SetDefaultUser("test-user")
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
		Filename:         s.cookieFile,
	})
	c.Assert(err, qt.IsNil)
	url, err := url.Parse(s.srv.URL)
	c.Assert(err, qt.IsNil)
	cookies := jar.Cookies(url)
	for _, cookie := range cookies {
		c.Assert(strings.HasPrefix(cookie.Name, "macaroon-"), qt.Equals, false, qt.Commentf("cookie %s found", cookie.Name))
	}
}

func isNonEmptyFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		panic(err)
	}
	return fi.Size() > 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		panic(err)
	}
	return true
}
