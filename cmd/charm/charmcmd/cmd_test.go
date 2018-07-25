// Copyright 2014 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd_test

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/cmd"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/loggo"
	"github.com/juju/mgotest"
	"github.com/juju/utils"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charm.v6"
	"gopkg.in/juju/charmrepo.v4/csclient"
	"gopkg.in/juju/charmrepo.v4/csclient/params"
	"gopkg.in/juju/charmstore.v5"
	"gopkg.in/juju/idmclient.v1/idmtest"
	bakery2u "gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery"
	yaml "gopkg.in/yaml.v2"

	"github.com/juju/charmstore-client/cmd/charm/charmcmd"
)

// run runs a charm plugin subcommand with the given arguments,
// its context directory set to dir. It returns the output of the command
// and its exit code.
func run(dir string, args ...string) (stdout, stderr string, exitCode int) {
	// Remove the warning writer usually registered by cmd.Log.Start, so that
	// it is possible to run multiple commands in the same test.
	// We are not interested in possible errors here.
	defer loggo.RemoveWriter("warning")
	var stdoutBuf, stderrBuf bytes.Buffer
	ctxt := &cmd.Context{
		Dir:    dir,
		Stdin:  nil,
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
	}
	exitCode = cmd.Main(charmcmd.New(), ctxt, args)
	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

func fakeHome(c *qt.C) {
	oldHome := utils.Home()
	utils.SetHome(c.Mkdir())
	c.AddCleanup(func() {
		utils.SetHome(oldHome)
	})
	err := os.MkdirAll(osenv.JujuXDGDataHomeDir(), 0755)
	c.Assert(err, qt.Equals, nil)
}

// charmstoreEnv sets up a running charmstore environment for use with
// tests.
type charmstoreEnv struct {
	database *mgotest.Database
	srv      *httptest.Server
	handler  charmstore.HTTPCloseHandler

	dockerSrv             *httptest.Server
	dockerRegistry        *httptest.Server
	dockerAuthServer      *httptest.Server
	dockerHandler         *dockerHandler
	dockerAuthHandler     *dockerAuthHandler
	dockerRegistryHandler *dockerRegistryHandler
	dockerHost            string

	cookieFile   string
	client       *csclient.Client
	serverParams charmstore.ServerParams
	discharger   *idmtest.Server
}

const minUploadPartSize = 100 * 1024

// initCharmstoreEnv initialises a new charmstore environment for a test.
func initCharmstoreEnv(c *qt.C) *charmstoreEnv {
	var env charmstoreEnv
	var err error
	env.database, err = mgotest.New()
	if errgo.Cause(err) == mgotest.ErrDisabled {
		c.Skip(err)
	}
	c.Assert(err, qt.Equals, nil)
	c.AddCleanup(func() {
		env.database.Close()
	})

	env.dockerHandler = newDockerHandler()
	env.dockerSrv = httptest.NewServer(env.dockerHandler)
	c.AddCleanup(env.dockerSrv.Close)
	env.dockerAuthHandler = newDockerAuthHandler()
	env.dockerAuthServer = httptest.NewServer(env.dockerAuthHandler)
	c.AddCleanup(env.dockerAuthServer.Close)
	env.dockerRegistryHandler = newDockerRegistryHandler(env.dockerAuthServer.URL)
	env.dockerRegistry = httptest.NewTLSServer(env.dockerRegistryHandler)
	c.AddCleanup(env.dockerRegistry.Close)

	dockerURL, err := url.Parse(env.dockerSrv.URL)
	c.Assert(err, qt.Equals, nil)
	env.dockerHost = dockerURL.Host

	c.Setenv("DOCKER_HOST", env.dockerSrv.URL)

	env.discharger = idmtest.NewServer()
	c.AddCleanup(env.discharger.Close)
	env.discharger.AddUser("charmstoreuser")
	env.serverParams = charmstore.ServerParams{
		AuthUsername:          "test-user",
		AuthPassword:          "test-password",
		IdentityLocation:      env.discharger.URL.String(),
		AgentKey:              bakery2uKeyPair(env.discharger.UserPublicKey("charmstoreuser")),
		AgentUsername:         "charmstoreuser",
		PublicKeyLocator:      bakeryV2LocatorToV2uLocator{env.discharger},
		MinUploadPartSize:     minUploadPartSize,
		DockerRegistryAddress: env.dockerHost,
	}
	env.handler, err = charmstore.NewServer(env.database.Database, nil, "", env.serverParams, charmstore.V5)
	c.Assert(err, qt.Equals, nil)
	c.AddCleanup(env.handler.Close)
	env.srv = httptest.NewServer(env.handler)
	c.AddCleanup(env.srv.Close)
	env.client = csclient.New(csclient.Params{
		URL:      env.srv.URL,
		User:     env.serverParams.AuthUsername,
		Password: env.serverParams.AuthPassword,
	})
	c.Patch(charmcmd.CSClientServerURL, env.srv.URL)
	env.cookieFile = filepath.Join(c.Mkdir(), "cookies")
	c.Setenv("GOCOOKIES", env.cookieFile)
	c.Setenv("JUJU_LOGGING_CONFIG", "DEBUG")
	return &env
}

func (e *charmstoreEnv) uploadCharmDir(c *qt.C, id *charm.URL, promulgatedRevision int, ch *charm.CharmDir) {
	var buf bytes.Buffer
	hash := sha512.New384()
	w := io.MultiWriter(hash, &buf)
	err := ch.ArchiveTo(w)
	c.Assert(err, qt.Equals, nil)
	e.addEntity(c, id, promulgatedRevision, hash.Sum(nil), bytes.NewReader(buf.Bytes()))
	err = e.client.Put("/"+id.Path()+"/meta/perm/read", []string{params.Everyone, id.User})
	c.Assert(err, qt.Equals, nil)
}

func (e *charmstoreEnv) uploadBundleDir(c *qt.C, id *charm.URL, promulgatedRevision int, b *charm.BundleDir) {
	var buf bytes.Buffer
	hash := sha512.New384()
	w := io.MultiWriter(hash, &buf)
	err := b.ArchiveTo(w)
	c.Assert(err, qt.Equals, nil)
	e.addEntity(c, id, promulgatedRevision, hash.Sum(nil), bytes.NewReader(buf.Bytes()))
	err = e.client.Put("/"+id.Path()+"/meta/perm/read", []string{params.Everyone, id.User})
	c.Assert(err, qt.Equals, nil)
}

func (e *charmstoreEnv) uploadResource(c *qt.C, id *charm.URL, name string, content string) {
	_, err := e.client.UploadResource(id, name, "", strings.NewReader(content), int64(len(content)), nil)
	c.Assert(err, qt.Equals, nil)
}

func (e *charmstoreEnv) addEntity(c *qt.C, id *charm.URL, promulgatedRevision int, hash []byte, body *bytes.Reader) {
	url := fmt.Sprintf("/%s/archive?hash=%x", id.Path(), hash)
	if promulgatedRevision != -1 {
		pid := *id
		pid.User = ""
		pid.Revision = promulgatedRevision
		url += fmt.Sprintf("&promulgated=%s", &pid)
	}
	req, err := http.NewRequest("PUT", "", body)
	c.Assert(err, qt.Equals, nil)
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = int64(body.Len())
	resp, err := e.client.Do(req, url)
	c.Assert(err, qt.Equals, nil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, qt.Equals, http.StatusOK)
	err = e.client.Put("/"+id.Path()+"/meta/perm/read", []string{params.Everyone})
	c.Assert(err, qt.Equals, nil)
}

func (e *charmstoreEnv) publish(c *qt.C, id *charm.URL, channels ...params.Channel) {
	path := id.Path()
	err := e.client.Put("/"+path+"/publish", params.PublishRequest{
		Channels: channels,
	})
	c.Assert(err, qt.Equals, nil)
	err = e.client.Put("/"+path+"/meta/perm/read", []string{
		params.Everyone, id.User,
	})
	c.Assert(err, qt.Equals, nil)
}

func TestCmd(t *testing.T) {
	RunSuite(qt.New(t), &cmdSuite{})
}

type cmdSuite struct {
	*charmstoreEnv
}

func (s *cmdSuite) Init(c *qt.C) {
	fakeHome(c)
	s.charmstoreEnv = initCharmstoreEnv(c)
}

func (s *cmdSuite) TestServerURLFromEnvContext(c *qt.C) {
	// We use the info command as a stand-in for
	// all of the commands, because it is testing
	// functionality in newCharmStoreClient,
	// which all commands use to create the charm
	// store client.

	// Point the default server URL to an invalid URL.
	c.Patch(charmcmd.CSClientServerURL, "invalid-url")

	// A first call fails.
	_, stderr, code := run(c.Mkdir(), "show", "--list")
	c.Assert(stderr, qt.Matches, "ERROR cannot get metadata endpoints: Get invalid-url/v5/meta/: .*\n")
	c.Assert(code, qt.Equals, 1)

	// After setting the JUJU_CHARMSTORE variable, the call succeeds.
	c.Setenv("JUJU_CHARMSTORE", s.srv.URL)
	_, stderr, code = run(c.Mkdir(), "show", "--list")
	c.Assert(stderr, qt.Matches, "")
	c.Assert(code, qt.Equals, 0)
}

type bakeryV2LocatorToV2uLocator struct {
	locator bakery.ThirdPartyLocator
}

// PublicKeyForLocation implements bakery2u.PublicKeyLocator.
func (l bakeryV2LocatorToV2uLocator) PublicKeyForLocation(loc string) (*bakery2u.PublicKey, error) {
	info, err := l.locator.ThirdPartyInfo(context.TODO(), loc)
	if err != nil {
		return nil, err
	}
	return bakery2uKey(&info.PublicKey), nil
}

func bakery2uKey(key *bakery.PublicKey) *bakery2u.PublicKey {
	var key2u bakery2u.PublicKey
	copy(key2u.Key[:], key.Key[:])
	return &key2u
}

func bakery2uKeyPair(key *bakery.KeyPair) *bakery2u.KeyPair {
	var key2u bakery2u.KeyPair
	copy(key2u.Public.Key[:], key.Public.Key[:])
	copy(key2u.Private.Key[:], key.Private.Key[:])
	return &key2u
}

func assertYAMLEquals(c *qt.C, got string, expect interface{}) {
	var expectv, gotv interface{}
	err := yaml.Unmarshal([]byte(got), &gotv)
	c.Assert(err, qt.Equals, nil)
	data, err := yaml.Marshal(expect)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(data, &expectv); err != nil {
		panic(err)
	}
	c.Assert(gotv, qt.DeepEquals, expectv)
}

func assertJSONEquals(c *qt.C, got string, expect interface{}) {
	var expectv, gotv interface{}
	err := json.Unmarshal([]byte(got), &gotv)
	c.Assert(err, qt.Equals, nil)
	data, err := json.Marshal(expect)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, &expectv); err != nil {
		panic(err)
	}
	c.Assert(gotv, qt.DeepEquals, expectv)
}
