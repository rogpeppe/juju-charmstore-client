// Copyright 2015 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd

import (
	"github.com/juju/cmd"
	"github.com/juju/gnuflag"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/charmrepo.v4/csclient/params"
)

type loginCommand struct {
	cmd.CommandBase
	auth authInfo
}

var loginDoc = `
The login command uses Ubuntu SSO to obtain security credentials for the charm store.

   charm login
`

func (c *loginCommand) Info() *cmd.Info {
	return &cmd.Info{
		Name:    "login",
		Purpose: "login to the charm store",
		Doc:     loginDoc,
	}
}

func (c *loginCommand) SetFlags(f *gnuflag.FlagSet) {
	addAuthFlags(f, &c.auth)
}

func (c *loginCommand) Run(ctxt *cmd.Context) error {
	client, err := newCharmStoreClient(ctxt, c.auth, params.NoChannel)
	if err != nil {
		return errgo.Notef(err, "cannot create charm store client")
	}
	defer client.jar.Save()
	return errgo.Mask(client.Login())
}
