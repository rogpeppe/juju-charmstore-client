// Copyright 2014-2016 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/loggo"
	"github.com/juju/persistent-cookiejar"
	planscmd "github.com/juju/plans-client/cmd"
	termscmd "github.com/juju/terms-client/cmd"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/errgo.v1"
	charm "gopkg.in/juju/charm.v6"
	"gopkg.in/juju/charmrepo.v4/csclient"
	"gopkg.in/juju/charmrepo.v4/csclient/params"
	esform "gopkg.in/juju/environschema.v1/form"
	"gopkg.in/juju/worker.v1"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"

	"github.com/juju/charmstore-client/internal/iomon"
)

var logger = loggo.GetLogger("charm.cmd.charm")

const (
	// cmdName holds the name of the super command.
	cmdName = "charm"

	// cmdDoc holds the super command description.
	cmdDoc = `
The charm command provides commands and tools
that access the Juju charm store.
`
)

// New returns a command that can execute charm commands.
func New() *cmd.SuperCommand {
	var c *cmd.SuperCommand
	notifyHelp := func(arg []string) {
		if len(arg) == 0 {
			registerPlugins(c)
		}
	}

	c = cmd.NewSuperCommand(cmd.SuperCommandParams{
		Name:            cmdName,
		Doc:             cmdDoc,
		Purpose:         "tools for accessing the charm store",
		MissingCallback: runPlugin,
		Log: &cmd.Log{
			DefaultConfig: os.Getenv(osenv.JujuLoggingConfigEnvKey),
		},
		NotifyHelp: notifyHelp,
	})
	c.Register(&attachCommand{})
	c.Register(&grantCommand{})
	c.Register(&listCommand{})
	c.Register(&listResourcesCommand{})
	c.Register(&loginCommand{})
	c.Register(&logoutCommand{})
	c.Register(&pullCommand{})
	c.Register(&pullResourceCommand{})
	c.Register(&pushCommand{})
	c.Register(&releaseCommand{})
	c.Register(&revokeCommand{})
	c.Register(&setCommand{})
	c.Register(&showCommand{})
	c.Register(&termsCommand{})
	c.Register(&whoamiCommand{})

	// Register terms-client commands
	c.Register(termscmd.NewReleaseTermCommand())
	c.Register(termscmd.NewPushTermCommand())
	c.Register(termscmd.NewShowTermCommand())
	c.Register(termscmd.NewListTermsCommand())

	// Register plans-client commands
	c.Register(planscmd.NewAttachCommand())
	c.Register(planscmd.NewPushCommand())
	c.Register(planscmd.NewResumeCommand())
	c.Register(planscmd.NewShowRevisionsCommand())
	c.Register(planscmd.NewShowCommand())
	c.Register(planscmd.NewSuspendCommand())
	c.Register(planscmd.NewListPlansCommand())

	c.AddHelpTopicCallback(
		"plugins",
		"Show "+c.Name+" plugins",
		func() string {
			return pluginHelpTopic()
		},
	)
	return c
}

// Expose the charm store server URL so that
// it can be changed for testing purposes.
var csclientServerURL = csclient.ServerURL

// serverURL returns the charm store server URL.
// The returned value can be overridden by setting the JUJU_CHARMSTORE
// environment variable.
func serverURL() string {
	if url := os.Getenv("JUJU_CHARMSTORE"); url != "" {
		return url
	}
	return csclientServerURL
}

// csClient embeds a charm store client and holds its associated HTTP client
// and cookie jar.
type csClient struct {
	*csclient.Client
	jar  *cookiejar.Jar
	ctxt *cmd.Context
	// filler holds the form filler used to interact with
	// the user when authenticating.
	filler *progressClearFiller
}

// SaveJAR calls save on the jar member variable. This follows the Law
// of Demeter and allows csClient to meet interfaces.
func (c *csClient) SaveJAR() error {
	return c.jar.Save()
}

// MinMultipartUploadSize holds the minimum size of upload to trigger
// multipart uploads. If zero, the default will be used.
var MinMultipartUploadSize int64

// newCharmStoreClient creates and return a charm store client with access to
// the associated HTTP client and cookie jar used to save authorization
// macaroons. If authUsername and authPassword are provided, the resulting
// client will use HTTP basic auth with the given credentials. The charm store
// client will use the given channel for its operations.
func newCharmStoreClient(ctxt *cmd.Context, auth authInfo, channel params.Channel) (*csClient, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
		Filename:         cookiejar.DefaultCookieFile(),
	})
	if err != nil {
		return nil, err
	}
	bakeryClient := httpbakery.NewClient()
	bakeryClient.Jar = jar
	filler := &progressClearFiller{
		f: &esform.IOFiller{
			In:  ctxt.Stdin,
			Out: ctxt.Stdout,
		},
	}
	var agentInfo *agent.AuthInfo
	if auth.agentFile != "" {
		ai, err := readAgentFile(ctxt.AbsPath(auth.agentFile))
		if err != nil {
			return nil, errgo.Notef(err, "cannot load agent information")
		}
		agentInfo = ai
	} else if ai, err := agent.AuthInfoFromEnvironment(); err == nil {
		agentInfo = ai
	} else if errgo.Cause(err) != agent.ErrNoAuthInfo {
		return nil, errgo.Mask(err)
	}
	if agentInfo != nil {
		if err := agent.SetUpAuth(bakeryClient, agentInfo); err != nil {
			return nil, errgo.Notef(err, "cannot set up agent authentication")
		}
	} else if !auth.noBrowser {
		bakeryClient.AddInteractor(httpbakery.WebBrowserInteractor{})
	}
	csClient := csClient{
		filler: filler,
		Client: csclient.New(csclient.Params{
			URL:          serverURL(),
			BakeryClient: bakeryClient,
			User:         auth.username,
			Password:     auth.password,
		}).WithChannel(channel),
		jar:  jar,
		ctxt: ctxt,
	}
	if MinMultipartUploadSize > 0 {
		csClient.SetMinMultipartUploadSize(MinMultipartUploadSize)
	}
	return &csClient, nil
}

// addChannelFlag adds the -c (--channel) flags to the given flag set.
// The channels argument is the set of allowed channels.
func addChannelFlag(f *gnuflag.FlagSet, cv *chanValue, channels []params.Channel) {
	if len(channels) == 0 {
		channels = params.OrderedChannels
	}
	chans := make([]string, len(channels))
	for i, ch := range channels {
		chans[i] = string(ch)
	}
	f.Var(cv, "c", fmt.Sprintf("the channel the charm or bundle is assigned to (%s)", strings.Join(chans, "|")))
	f.Var(cv, "channel", "")
}

// chanValue is a gnuflag.Value that stores a channel name
// ("stable", "candidate", "beta", "edge" or "unpublished").
type chanValue struct {
	C params.Channel
}

// Set implements gnuflag.Value.Set by setting the channel value.
func (cv *chanValue) Set(s string) error {
	cv.C = params.Channel(s)
	if cv.C == params.DevelopmentChannel {
		logger.Warningf("the development channel is deprecated: automatically switching to the edge channel")
		cv.C = params.EdgeChannel
	}
	return nil
}

// String implements gnuflag.Value.String.
func (cv *chanValue) String() string {
	return string(cv.C)
}

func addUploadIdCacheFlag(f *gnuflag.FlagSet, cachePath *string) {
	f.StringVar(cachePath, "resume-cache-dir", osenv.JujuXDGDataHomePath("charm-upload-cache"), "path to resource upload resumption cache (if empty, no cache will be used)")
}

// addAuthFlags adds authentication-related flags to the given flag set.
func addAuthFlags(f *gnuflag.FlagSet, info *authInfo) {
	f.Var(info, "auth", "user:passwd to use for basic HTTP authentication")
	f.StringVar(&info.agentFile, "a", "", "name of file containing agent login details")
	f.StringVar(&info.agentFile, "agent", "", "")
	f.BoolVar(&info.noBrowser, "B", false, "do not use web browser for authentication")
	f.BoolVar(&info.noBrowser, "no-browser-login", false, "")
}

type authInfo struct {
	agentFile string
	username  string
	password  string
	noBrowser bool
}

// Set implements gnuflag.Value.Set by validating
// the authentication flag.
func (a *authInfo) Set(s string) error {
	if s == "" {
		*a = authInfo{}
		return nil
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return errgo.New(`invalid auth credentials: expected "user:passwd"`)
	}
	if parts[0] == "" {
		return errgo.Newf("empty username")
	}
	a.username, a.password = parts[0], parts[1]
	return nil
}

// String implements gnuflag.Value.String.
func (a *authInfo) String() string {
	if a.username == "" && a.password == "" {
		return ""
	}
	return a.username + ":" + a.password
}

type progressClearFiller struct {
	f       esform.Filler
	mu      sync.Mutex
	display *progressDisplay
}

func (filler *progressClearFiller) setDisplay(display *progressDisplay) {
	filler.mu.Lock()
	defer filler.mu.Unlock()
	filler.display = display
}

func (filler *progressClearFiller) setDisplayEnabled(enabled bool) {
	filler.mu.Lock()
	defer filler.mu.Unlock()
	if filler.display != nil {
		filler.display.setEnabled(enabled)
	}
}

func (filler *progressClearFiller) Fill(f esform.Form) (map[string]interface{}, error) {
	// Disable status update while the form is being filled out.
	filler.setDisplayEnabled(false)
	defer filler.setDisplayEnabled(true)
	return filler.f.Fill(f)
}

type progressDisplay struct {
	w           io.Writer
	monitor     *iomon.Monitor
	printer     *iomon.Printer
	setUploadId func(uploadId string)
	quiet       bool

	mu      sync.Mutex
	enabled bool
}

func newProgressDisplay(name string, w io.Writer, quiet bool, size int64, setUploadId func(id string)) *progressDisplay {
	d := &progressDisplay{
		w:           w,
		enabled:     true,
		setUploadId: setUploadId,
		quiet:       quiet,
	}
	if !quiet {
		d.printer = iomon.NewPrinter(w, name)
	}
	d.monitor = iomon.New(iomon.Params{
		Size:   size,
		Setter: d,
	})
	return d
}

// SetStatus implements iomon.StatusSetter. It doesn't
// print the status if display is disabled.
func (d *progressDisplay) SetStatus(s iomon.Status) {
	if d.isEnabled() {
		d.printer.SetStatus(s)
	}
}

func (d *progressDisplay) setEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.printer != nil {
		d.printer.Clear()
	}
	d.enabled = enabled
}

func (d *progressDisplay) Start(uploadId string, expires time.Time) {
	if uploadId != "" && d.setUploadId != nil {
		d.setUploadId(uploadId)
	}
}

func (d *progressDisplay) close() {
	d.stopMonitor()
}

// Transferred implements csclient.Progress.Transferred.
func (d *progressDisplay) Transferred(n int64) {
	// d.monitor should always be non-nil because Transferred
	// should never be called after Finalizing but be defensive just in case.
	if d.monitor != nil {
		d.monitor.Update(n)
	}
}

func (d *progressDisplay) isEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled && !d.quiet
}

// Error implements csclient.Progress.Error.
func (d *progressDisplay) Error(err error) {
	if d.monitor != nil && d.isEnabled() {
		d.printer.Clear()
	}
	logger.Warningf("%v", err)
}

// Finalizing implements csclient.Progress.Finalizing.
func (d *progressDisplay) Finalizing() {
	d.stopMonitor()
	if !d.quiet {
		fmt.Fprintf(d.w, "finalizing upload\n")
	}
}

func (d *progressDisplay) stopMonitor() {
	if d.monitor == nil {
		return
	}
	worker.Stop(d.monitor)
	d.monitor = nil
	if d.isEnabled() {
		d.printer.Done()
	}
}

func readAgentFile(f string) (*agent.AuthInfo, error) {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, errgo.Mask(err, os.IsNotExist)
	}
	var v agent.AuthInfo
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, errgo.Notef(err, "cannot parse agent data from %q", f)
	}
	return &v, nil
}

// charmMetadata returns the resolved charm URL and the
// charm metadata for the given URL.
func charmMetadata(client *csClient, id *charm.URL) (*charm.URL, *charm.Meta, error) {
	var meta struct {
		CharmMetadata charm.Meta
	}
	id, err := client.Meta(id, &meta)
	if err != nil {
		return nil, nil, errgo.Mask(err)
	}
	return id, &meta.CharmMetadata, nil
}
