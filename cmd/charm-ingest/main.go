// Copyright 2018 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/juju/charmstore-client/internal/ingest"
	"github.com/juju/gnuflag"
	"github.com/juju/persistent-cookiejar"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charmrepo.v4/csclient"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
)

var printCmdUsage = func() {
	fmt.Printf("usage: charm-ingest [flags] whitelist destination\n\n")
	gnuflag.PrintDefaults()
	fmt.Println(`
Charm-ingest copies a set of charms and bundles from one charmstore to another.

The whitelist file specifies which entities to copy. Each line holds a charm or bundle
id (for example cs:~bob/mycharm) followed by an optional space-separated set of channels
to consider for copying. If no channels are provided for an entity, the stable channel
will be used. If no revision is given, the latest revision for the specified channel
will be copied. If a bundle is specified, all charms mentioned by the bundle will also
be transferred.

For example, the following whitelist specifies that the latest stable revision
of the wordpress charm should be transferred, and revision 254 of the
canonical-kubernetes bundle with all its charm dependencies should
be made available in the beta and stable channels.

	wordpress
	cs:bundle/canonical-kubernetes-254 beta stable

By default, entities will be copied from the global charm store (https://api.jujucharms.com/charmstore);
this can be overridden by setting the JUJU_CHARMSTORE environment variable.

The destination argument holds the URL of the charm store to copy charms into.
The auth flag can be used to specify the admin username and password for the destination;
if not specified, the user will be authenticated with the Candid identity service.
Currently there is no way to specify username/password for the source charmstore.`)
}

func main() {
	debug := gnuflag.Bool("debug", false, "show debugging messages")
	maxDisk := gnuflag.Int64("maxdisk", 0, "max disk space to use (0 means unlimited)")
	hardDiskLimit := gnuflag.Bool("hardlimit", false, "do not transfer any resources larger than the disk limit")
	var auth authInfo
	gnuflag.Var(&auth, "auth", "user:passwd to use for basic HTTP authentication to destination URL")
	gnuflag.Usage = func() {
		printCmdUsage()
		os.Exit(2)
	}

	gnuflag.Parse(true)
	if gnuflag.NArg() != 2 {
		gnuflag.Usage()
	}

	fileName := gnuflag.Arg(0)
	destURL := gnuflag.Arg(1)

	whitelist, err := parseWhitelistFile(fileName)
	if err != nil {
		fatalf("unable to parse whitelist: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		fatalf("unable to create cookie jar: %v", err)
	}
	defer func() {
		err := jar.Save()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to save cookie jar: %v\n", err)
		}
	}()

	bakeryClient := httpbakery.NewClient()
	bakeryClient.Jar = jar
	bakeryClient.AddInteractor(httpbakery.WebBrowserInteractor{})

	p := ingest.IngestParams{
		Src:           newCharmStoreClient(sourceURL(), bakeryClient, nil),
		Dest:          newCharmStoreClient(destURL, bakeryClient, &auth),
		Whitelist:     whitelist,
		MaxDisk:       *maxDisk,
		SoftDiskLimit: !*hardDiskLimit,
	}
	if *debug {
		p.Log = func(s string) {
			log.Println(s)
		}
	}
	stats := ingest.Ingest(p)

	for _, e := range stats.Errors {
		// TODO add a callback to IngestParams so that we can print these as they happen?
		fmt.Fprintf(os.Stderr, "error: %v\n", e)
	}

	fmt.Printf("total %d revisions of %d entities\n", stats.EntityCount, stats.BaseEntityCount)
	if stats.ArchivesCopiedCount > 0 {
		fmt.Printf("copied %d revisions\n", stats.ArchivesCopiedCount)
	} else {
		fmt.Println("no revisions copied")
	}
	if stats.FailedEntityCount > 0 {
		fmt.Printf("failed to copy %d revisions\n", stats.FailedEntityCount)
	}
}

// parseWhitelistFile takes a file name, and parses the whitelist from that file
// returning whitelist entities. An error is returned if a file is unable to be
// opened from the provided path, or the file is not a valid whitelist.
func parseWhitelistFile(fileName string) ([]ingest.WhitelistEntity, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseWhitelist(fileName, file)
}

// newCharmStoreClient creates a new client to connect at the given url, with the
// bakery client provided and optional authUsername and authPassword.
func newCharmStoreClient(url string, bakeryClient *httpbakery.Client, auth *authInfo) *csclient.Client {
	p := csclient.Params{
		URL:          url,
		BakeryClient: bakeryClient,
	}
	if auth != nil {
		p.User = auth.username
		p.Password = auth.password
	}
	return csclient.New(p)
}

// sourceURL returns the charm store server URL.
// The returned value can be overridden by setting the JUJU_CHARMSTORE
// environment variable.
func sourceURL() string {
	if url := os.Getenv("JUJU_CHARMSTORE"); url != "" {
		return url
	}
	return csclient.ServerURL
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

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Println()
	os.Exit(1)
}
