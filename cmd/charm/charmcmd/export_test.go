// Copyright 2014-2016 Canonical Ltd.
// Licensed under the GPLv3, see LICENCE file for details.

package charmcmd

var (
	ClientGetArchive                       = &clientGetArchive
	CSClientServerURL                      = &csclientServerURL
	PluginTopicText                        = pluginTopicText
	ServerURL                              = serverURL
	PluginDescriptionLastCallReturnedCache = &pluginDescriptionLastCallReturnedCache
	WhiteListedCommands                    = whiteListedCommands
)

func ResetPluginDescriptionsResults() {
	pluginDescriptionsResults = nil
}
