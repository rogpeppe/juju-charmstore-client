// Copyright 2014-2016 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"github.com/juju/idmclient/ussologin"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/loggo"
	"github.com/juju/persistent-cookiejar"
	"github.com/juju/usso"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charm.v6-unstable"
	"gopkg.in/juju/charmrepo.v2-unstable/csclient"
	"gopkg.in/juju/charmrepo.v2-unstable/csclient/params"
	esform "gopkg.in/juju/environschema.v1/form"
	"gopkg.in/juju/worker.v1"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
	hbform "gopkg.in/macaroon-bakery.v1/httpbakery/form"
	httpbakery2 "gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

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
	c.Register(&pushCommand{})
	c.Register(&releaseCommand{})
	c.Register(&revokeCommand{})
	c.Register(&setCommand{})
	c.Register(&showCommand{})
	c.Register(&termsCommand{})
	c.Register(&whoamiCommand{})
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
		return nil, errgo.New("cannot load the cookie jar")
	}
	bakeryClient := httpbakery.NewClient()
	bakeryClient.Jar = jar
	tokenStore := ussologin.NewFileTokenStore(ussoTokenPath())
	filler := &progressClearFiller{
		f: &esform.IOFiller{
			In:  ctxt.Stdin,
			Out: ctxt.Stdout,
		},
	}
	bakeryClient2 := httpbakery2.NewClient()
	bakeryClient2.Jar = jar
	bakeryClient.WebPageVisitor = httpbakery.NewMultiVisitor(
		visitorAdaptor{
			client2:  bakeryClient2,
			visitor2: ussologin.NewVisitor("charm", filler, tokenStore),
		},
		hbform.Visitor{filler},
		httpbakery.WebBrowserVisitor,
	)
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
	return &csClient, nil
}

func uploadResource(ctxt *cmd.Context, client *csClient, charmId *charm.URL, name, file string) (rev int, err error) {
	file = ctxt.AbsPath(file)
	f, err := os.Open(file)
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, errgo.Mask(err)
	}
	d := newProgressDisplay(file, ctxt.Stdout, info.Size())
	defer d.close()
	client.filler.setDisplay(d)
	defer client.filler.setDisplay(nil)
	rev, err = client.UploadResource(charmId, name, file, f, info.Size(), d)
	if err != nil {
		return 0, errgo.Notef(err, "can't upload resource")
	}
	return rev, nil
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

// addAuthFlag adds the authentication flag to the given flag set.
func addAuthFlag(f *gnuflag.FlagSet, info *authInfo) {
	f.Var(info, "auth", "user:passwd to use for basic HTTP authentication")
}

type authInfo struct {
	username string
	password string
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

func ussoTokenPath() string {
	return osenv.JujuXDGDataHomePath("store-usso-token")
}

// translateError translates err into a new error with a more
// understandable error message. If err is not translated then it will be
// returned unchanged.
func translateError(err error) error {
	if err == nil {
		return err
	}
	cause := errgo.Cause(err)
	switch {
	case httpbakery.IsInteractionError(cause):
		err := translateInteractionError(cause.(*httpbakery.InteractionError))
		return errgo.Notef(err, "login failed")
	}
	return err
}

// translateInteractionError translates err into a new error with a user
// understandable error message.
func translateInteractionError(err *httpbakery.InteractionError) error {
	ussoError, ok := errgo.Cause(err.Reason).(*usso.Error)
	if !ok {
		return err.Reason
	}
	if ussoError.Code != "INVALID_DATA" {
		return ussoError
	}
	for k, v := range ussoError.Extra {
		// Only report the first error, this will be an arbitrary
		// field from the extra information. In general the extra
		// information only contains one item.
		if k == "email" {
			// Translate email to username so that it matches the prompt.
			k = "username"
		}
		if v1, ok := v.([]interface{}); ok && len(v1) > 0 {
			v = v1[0]
		}
		return errgo.Newf("%s: %s", k, v)
	}
	return ussoError
}

// visitorAdaptor implements httpbakery.Visitor (v1 bakery) by calling a
// v2-unstable Visitor implementation. This is a temporary necessity
// because tests use v2 bakery because the charmstore server
// implementation uses that version, but the charmstore client must use
// v1 bakery because charmrepo uses that version (and can't move away
// from it until juju is updated to use bakery.v2).
//
// The conflict comes from the fact that both client and server side use
// idmclient, which is not versioned.
//
// This adaptor makes it possible to use the ussologin Visitor
// implementation in the v1 bakery client.
type visitorAdaptor struct {
	client2  *httpbakery2.Client
	visitor2 httpbakery2.Visitor
}

func (a visitorAdaptor) VisitWebPage(c *httpbakery.Client, u map[string]*url.URL) error {
	return a.visitor2.VisitWebPage(a.client2, u)
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
	w       io.Writer
	monitor *iomon.Monitor
	printer *iomon.Printer

	mu      sync.Mutex
	enabled bool
}

func newProgressDisplay(name string, w io.Writer, size int64) *progressDisplay {
	d := &progressDisplay{
		w:       w,
		printer: iomon.NewPrinter(w, name),
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
	logger.Infof("enabled: %s", d.isEnabled())
	if d.isEnabled() {
		d.printer.SetStatus(s)
	}
}

func (d *progressDisplay) setEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.printer.Clear()
	d.enabled = enabled
}

func (d *progressDisplay) Start(uploadId string, expires time.Time) {
	// TODO print upload id and tell user about resume feature
}

func (d *progressDisplay) close() {
	d.stopMonitor()
}

// Transferred implements csclient.Progress.Transferred.
func (d *progressDisplay) Transferred(n int64) {
	// d.monitor should always be non-nil because Transferred
	// should never be called after Finalizing but be defensive just in case.
	logger.Infof("Transferred %p %v", d.monitor, n)
	if d.monitor != nil {
		d.monitor.Update(n)
	}
}

func (d *progressDisplay) isEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// Transferred implements csclient.Progress.Transferred.
func (d *progressDisplay) Error(err error) {
	if d.monitor != nil && d.isEnabled() {
		d.printer.Clear()
	}
	logger.Warningf("%v", err)
}

func (d *progressDisplay) Finalizing() {
	d.stopMonitor()
	fmt.Fprintf(d.w, "finalizing upload\n")
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
