// Copyright 2016 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/juju/cmd"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charmrepo.v4/csclient/params"
	"gopkg.in/macaroon.v2"
)

type logoutCommand struct {
	cmd.CommandBase
}

var logoutDoc = `
The logout command removes all security credentials for the charm store.

   charm logout
`

func (c *logoutCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "logout",
		Purpose: "logout from the charm store",
		Doc:     logoutDoc,
	}
}

func (c *logoutCommand) Run(ctxt *cmd.Context) error {
	client, err := newCharmStoreClient(ctxt, authInfo{}, params.NoChannel)
	if err != nil {
		return errgo.Notef(err, "cannot create charm store client")
	}
	defer client.jar.Save()
	u, err := url.Parse(client.ServerURL())
	if err != nil {
		// If we can't parse the charmstore URL then we can't be
		// logged in to it.
		return nil
	}
	seen := map[string]bool{
		u.String(): true,
	}
	urls := []*url.URL{u}
	for i := 0; i < len(urls); i++ {
		for _, cookie := range client.jar.AllCookies() {
			// All login related cookies will be called macaroon-something.
			if !strings.HasPrefix(cookie.Name, "macaroon-") {
				continue
			}
			if !cookieForURL(cookie, urls[i]) {
				continue
			}
			ms, err := decodeMacaroonSlice(cookie.Value)
			if err != nil {
				continue
			}
			// Check for any third party caveats in the macaroon for
			// which we might also need to delete cookies.
			for _, m := range ms {
				for _, cav := range m.Caveats() {
					if cav.Location == "" {
						// First party
						continue
					}
					u, err := url.Parse(cav.Location)
					if err != nil {
						// If it's not a URL we won't have a cookie.
						continue
					}
					if seen[u.String()] {
						continue
					}
					seen[u.String()] = true
					urls = append(urls, u)
				}
			}
			client.jar.RemoveCookie(cookie)
		}
	}
	return nil
}

// decodeMacaroonSlice decodes a base64-JSON-encoded slice of macaroons from
// the given string.
func decodeMacaroonSlice(value string) (macaroon.Slice, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot base64-decode macaroons")
	}
	var ms macaroon.Slice
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, errgo.NoteMask(err, "cannot unmarshal macaroons")
	}
	return ms, nil
}

// cookieForURL determines if c would be sent in a request to u.
func cookieForURL(c *http.Cookie, u *url.URL) bool {
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if c.Domain != host {
		// In general this wouldn't be sufficient to determine if
		// a cookie applies to a host, but for the charmstore
		// services we know we are using hosts as domains.
		return false
	}
	path := strings.TrimSuffix(c.Path, "/")
	if path == u.Path {
		return true
	}
	if strings.HasPrefix(u.Path, path) && u.Path[len(path)] == '/' {
		return true
	}
	return false
}
