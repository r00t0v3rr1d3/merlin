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

package cli

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/agents"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/modules"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// Global Variables
var shellModule modules.Module
var shellAgent uuid.UUID
var shellListener listener
var shellListenerOptions map[string]string
var prompt *readline.Instance
var shellCompleter *readline.PrefixCompleter
var shellMenuContext = "main"

// MessageChannel is used to input user messages that are eventually written to STDOUT on the CLI application
var MessageChannel = make(chan messages.UserMessage)
var clientID = uuid.NewV4()

// Prevent the server from falling over from an accidental Ctrl-C
func osSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		if confirm("Are you sure you want to quit the server?") {
			exit()
		}
	}()
}

// Shell is the exported function to start the command line interface
func Shell() {

	osSignalHandler()
	shellCompleter = getCompleter("main")

	printUserMessage()
	registerMessageChannel()
	getUserMessages()

	p, err := readline.NewEx(&readline.Config{
		Prompt:              "\033[31mGandalf»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		AutoComplete:        shellCompleter,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error with the provided input: %s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	prompt = p

	defer func() {
		err := prompt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	log.SetOutput(prompt.Stderr())

	for {
		line, err := prompt.Readline()
		if err == readline.ErrInterrupt {
			if confirm("Are you sure you want to quit the server?") {
				exit()
			}
		} else if err == io.EOF {
			if confirm("Are you sure you want to quit the server?") {
				exit()
			}
		}

		line = strings.TrimSpace(line)
		//cmd := strings.Fields(line)
		cmd, err := shellwords.Parse(line)
		if err != nil {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing command line arguments:\r\n%s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}

		if len(cmd) > 0 {
			switch shellMenuContext {
			case "agent":
				handleAgentShell(uuid.Nil, cmd)
			case "listener":
				menuListener(cmd)
			case "listenersmain":
				menuListeners(cmd)
			case "listenersetup":
				menuListenerSetup(cmd)
			case "main":
				switch cmd[0] {
				case "agent":
					if len(cmd) > 1 {
						menuAgent(cmd[1:])
					}
				case "banner":
					m := "\n"
					m += color.WhiteString(banner.MerlinBanner2)
					m += color.WhiteString("\r\n\t\t   Version: %s", merlin.Version)
					m += color.WhiteString("\r\n\t\t   Build: %s", merlin.Build)
					m += color.WhiteString("\r\n\t\t   Codename: Gandalf\n")
					MessageChannel <- messages.UserMessage{
						Level:   messages.Plain,
						Message: m,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				case "help", "?":
					menuHelpMain()
				case "jobs":
					displayJobTable(agentAPI.GetCreatedJobs())
				case "queue":
					if len(cmd) > 2 {
						if cmd[1] == "all" {
							cmd[1] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
						}
						newID, err := uuid.FromString(cmd[1])
						if err != nil {
							MessageChannel <- messages.UserMessage{
								Level:   messages.Warn,
								Message: "Invalid uuid",
								Time:    time.Now().UTC(),
								Error:   true,
							}
						} else {
							handleAgentShell(newID, cmd[2:])
						}
					} else {
						MessageChannel <- messages.UserMessage{
							Level:   messages.Warn,
							Message: "Not enough arguments provided",
							Time:    time.Now().UTC(),
							Error:   true,
						}
					}
				case "quit":
					if len(cmd) > 1 {
						if strings.ToLower(cmd[1]) == "-y" {
							exit()
						}
					}
					if confirm("Are you sure you want to quit the server?") {
						exit()
					}
				case "interact":
					if len(cmd) > 1 {
						i := []string{"interact"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "listeners":
					shellMenuContext = "listenersmain"
					prompt.Config.AutoComplete = getCompleter("listenersmain")
					prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m]»\033[0m ")
				case "remove":
					if len(cmd) > 1 {
						i := []string{"remove"}
						i = append(i, cmd[1])
						menuAgent(i)
					}
				case "sessions":
					menuAgent([]string{"list"})
				case "set":
					if len(cmd) > 2 {
						switch cmd[1] {
						case "verbose":
							if strings.ToLower(cmd[2]) == "true" {
								core.Verbose = true
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Verbose output enabled",
									Time:    time.Now(),
									Error:   false,
								}
							} else if strings.ToLower(cmd[2]) == "false" {
								core.Verbose = false
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Verbose output disabled",
									Time:    time.Now(),
									Error:   false,
								}
							}
						case "debug":
							if strings.ToLower(cmd[2]) == "true" {
								core.Debug = true
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Debug output enabled",
									Time:    time.Now().UTC(),
									Error:   false,
								}
							} else if strings.ToLower(cmd[2]) == "false" {
								core.Debug = false
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: "Debug output disabled",
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						}
					}
				case "use":
					menuUse(cmd[1:])
				case "version":
					MessageChannel <- messages.UserMessage{
						Level:   messages.Plain,
						Message: color.BlueString("Gandalf version: %s\n", merlin.Version),
						Time:    time.Now().UTC(),
						Error:   false,
					}
				case "":
				default:
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						var x []string
						executeCommand(cmd[0], x)
					}
				}
			case "module":
				switch cmd[0] {
				case "back", "main":
					menuSetMain()
				case "info":
					shellModule.ShowInfo()
				case "quit":
					if len(cmd) > 1 {
						if strings.ToLower(cmd[1]) == "-y" {
							exit()
						}
					}
					if confirm("Are you sure you want to quit the server?") {
						exit()
					}
				case "reload":
					menuSetModule(strings.TrimSuffix(strings.Join(shellModule.Path, "/"), ".json"))
				case "run":
					modMessages := moduleAPI.RunModule(shellModule)
					for _, message := range modMessages {
						MessageChannel <- message
					}
				case "sessions":
					menuAgent([]string{"list"})
				case "set":
					if len(cmd) > 2 {
						if cmd[1] == "Agent" {
							s, err := shellModule.SetAgent(cmd[2])
							if err != nil {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Warn,
									Message: err.Error(),
									Time:    time.Now().UTC(),
									Error:   true,
								}
							} else {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: s,
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						} else {
							s, err := shellModule.SetOption(cmd[1], cmd[2:])
							if err != nil {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Warn,
									Message: err.Error(),
									Time:    time.Now().UTC(),
									Error:   true,
								}
							} else {
								MessageChannel <- messages.UserMessage{
									Level:   messages.Success,
									Message: s,
									Time:    time.Now().UTC(),
									Error:   false,
								}
							}
						}
					}
				case "show":
					if len(cmd) > 1 {
						switch cmd[1] {
						case "info":
							shellModule.ShowInfo()
						case "options":
							shellModule.ShowOptions()
						}
					}
				case "unset":
					if len(cmd) >= 2 {
						s, err := shellModule.SetOption(cmd[1], nil)
						if err != nil {
							MessageChannel <- messages.UserMessage{
								Level:   messages.Warn,
								Message: err.Error(),
								Time:    time.Now().UTC(),
								Error:   true,
							}
						} else {
							MessageChannel <- messages.UserMessage{
								Level:   messages.Success,
								Message: s,
								Time:    time.Now().UTC(),
								Error:   false,
							}
						}
					}
				case "help", "?":
					menuHelpModule()
				default:
					if len(cmd) > 1 {
						executeCommand(cmd[0], cmd[1:])
					} else {
						var x []string
						executeCommand(cmd[0], x)
					}
				}
			}
		}

	}
}

func menuUse(cmd []string) {
	if len(cmd) > 0 {
		switch cmd[0] {
		case "module":
			if len(cmd) > 1 {
				menuSetModule(cmd[1])
			} else {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "Invalid module",
					Time:    time.Now().UTC(),
					Error:   false,
				}
			}
		case "":
		default:
			MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "Invalid 'use' command",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	} else {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Note,
			Message: "Invalid 'use' command",
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
}

func menuAgent(cmd []string) {
	switch cmd[0] {
	case "list":
		header, rows := agentAPI.GetAgentsRows()
		displayTable(header, rows)
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "remove":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				MessageChannel <- agentAPI.Remove(i)
			}
		}
	}
}

func menuSetAgent(agentID uuid.UUID) {
	agentList := agentAPI.GetAgents()
	for _, id := range agentList {
		if agentID == id {
			shellAgent = agentID
			if agents.Agents[id].Platform == "windows" {
				prompt.Config.AutoComplete = getCompleter("agent-windows")
			} else {
				prompt.Config.AutoComplete = getCompleter("agent-nix")
			}
			prompt.SetPrompt("\033[31mGandalf[\033[32magent\033[31m][\033[33m" + shellAgent.String() + "\033[31m]»\033[0m ")
			shellMenuContext = "agent"
		}
	}
}

func handleAgentShell(curAgent uuid.UUID, cmd []string) {
	if uuid.Equal(uuid.Nil, curAgent) {
		curAgent = shellAgent
	}

	switch cmd[0] {
	case "back":
		menuSetMain()
	case "cd":
		MessageChannel <- agentAPI.CD(curAgent, cmd)
	case "clear", "c":
		MessageChannel <- agentAPI.ClearJobs(curAgent)
	case "cmd", "shell", "exec":
		MessageChannel <- agentAPI.CMD(curAgent, cmd)
	case "download":
		MessageChannel <- agentAPI.Download(curAgent, cmd)
	case "execute-assembly", "assembly":
		go func() { MessageChannel <- agentAPI.ExecuteAssembly(curAgent, cmd) }()
	case "execute-pe", "pe":
		go func() { MessageChannel <- agentAPI.ExecutePE(curAgent, cmd) }()
	case "execute-shellcode", "shinject":
		MessageChannel <- agentAPI.ExecuteShellcode(curAgent, cmd)
	case "exit": // Stock merlin calls this "kill"
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				menuSetMain()
				MessageChannel <- agentAPI.Exit(curAgent, cmd)
			}
		} else {
			if confirm("Are you sure you want to exit the agent?") {
				menuSetMain()
				MessageChannel <- agentAPI.Exit(curAgent, cmd)
			}
		}
	case "help", "?":
		menuHelpAgent(agents.Agents[curAgent].Platform)
	case "ifconfig", "ipconfig":
		MessageChannel <- agentAPI.Ipconfig(curAgent, cmd)
	case "inactivemultiplier":
		//MessageChannel <- agentAPI.SetInactiveMultiplier(curAgent, cmd)
	case "inactivethreshold":
		//MessageChannel <- agentAPI.SetInactiveThreshold(curAgent, cmd)
	case "info":
		rows, message := agentAPI.GetAgentInfo(curAgent)
		if message.Error {
			MessageChannel <- message
		} else {
			displayTable([]string{}, rows)
		}
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "ja3":
		MessageChannel <- agentAPI.SetJA3(curAgent, cmd)
	case "jobs":
		jobs, message := agentAPI.GetJobsForAgent(curAgent)
		if message.Message != "" {
			MessageChannel <- message
		}
		displayJobTable(jobs)
	case "kill": // Gandalf addition: kill a process
		MessageChannel <- agentAPI.KillProcess(curAgent, cmd)
	case "killdate":
		MessageChannel <- agentAPI.SetKillDate(curAgent, cmd)
	case "ls":
		MessageChannel <- agentAPI.LS(curAgent, cmd)
	case "main":
		menuSetMain()
	case "maxretry":
		MessageChannel <- agentAPI.SetMaxRetry(curAgent, cmd)
	case "netstat":
		//MessageChannel <- agentAPI.Netstat(curAgent, cmd)
	case "note":
		//newNote := ""
		//if len(cmd) > 1 {
		//newNote = strings.Join(cmd[1:], " ")
		//}
		//err := agents.SetNote(curAgent, newNote)
		//if err == nil {
		//MessageChannel <- messages.UserMessage{
		//Level:   messages.Success,
		//Message: fmt.Sprintf("Note set to: %s", strings.Join(cmd[1:], " ")),
		//Time:    time.Now().UTC(),
		//Error:   true,
		//}
		//} else {
		//MessageChannel <- messages.UserMessage{
		//Level:   messages.Warn,
		//Message: fmt.Sprintf("Error setting note: %s", err.Error()),
		//Time:    time.Now().UTC(),
		//Error:   true,
		//}
		//}
	case "nslookup":
		//MessageChannel <- agentAPI.Nslookup(curAgent, cmd)
	case "padding":
		MessageChannel <- agentAPI.SetPadding(curAgent, cmd)
	case "pipes":
		//MessageChannel <- agentAPI.Pipes(curAgent, cmd)
	case "ps":
		//MessageChannel <- agentAPI.PS(curAgent, cmd)
	case "pwd":
		MessageChannel <- agentAPI.PWD(curAgent, cmd)
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to quit the server?") {
			exit()
		}
	case "sessions":
		menuAgent([]string{"list"})
	case "sdelete":
		//MessageChannel <- agentAPI.SecureDelete(curAgent, cmd)
	case "sleep":
		MessageChannel <- agentAPI.SetSleep(curAgent, cmd)
	case "status":
		status, message := agentAPI.GetAgentStatus(curAgent)
		if message.Error {
			MessageChannel <- message
		}
		if status == "Active" {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.GreenString("%s agent is active\n", curAgent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else if status == "Delayed" {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.YellowString("%s agent is delayed\n", curAgent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else if status == "Dead" {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.RedString("%s agent is dead\n", curAgent),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		} else {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Plain,
				Message: color.BlueString("%s agent is %s\n", curAgent, status),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "touch", "timestomp":
		//MessageChannel <- agentAPI.Touch(curAgent, cmd)
	case "upload":
		MessageChannel <- agentAPI.Upload(curAgent, cmd)
	case "uptime":
		//MessageChannel <- agentAPI.Uptime(curAgent, cmd)
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			executeCommand(cmd[0], []string{})
		}
	}
}

// menuListener handles all the logic for interacting with an instantiated listener
func menuListener(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		shellMenuContext = "listenersmain"
		prompt.Config.AutoComplete = getCompleter("listenersmain")
		prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m]»\033[0m ")
	case "delete":
		if confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", shellListener.name)) {
			um := listenerAPI.Remove(shellListener.name)
			if !um.Error {
				shellListener = listener{}
				shellListenerOptions = nil
				shellMenuContext = "listenersmain"
				prompt.Config.AutoComplete = getCompleter("listenersmain")
				prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m]»\033[0m ")
			} else {
				MessageChannel <- um
			}
		}
	case "help", "?":
		menuHelpListener()
	case "info", "show":
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		statusMessage := listenerAPI.GetListenerStatus(shellListener.id)
		if statusMessage.Error {
			MessageChannel <- statusMessage
			break
		}
		shellListener.status = listenerAPI.GetListenerStatus(shellListener.id).Message
		if options != nil {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Value"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetBorder(true)

			for k, v := range options {
				table.Append([]string{k, v})
			}
			table.Append([]string{"Status", shellListener.status})
			table.Render()
		}
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "main":
		menuSetMain()
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to quit the server?") {
			exit()
		}
	case "restart":
		MessageChannel <- listenerAPI.Restart(shellListener.id)
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m][\033[33m" + options["Name"] + "\033[31m]»\033[0m ")
	case "sessions":
		menuAgent([]string{"list"})
	case "set":
		MessageChannel <- listenerAPI.SetOption(shellListener.id, cmd)
	case "start":
		MessageChannel <- listenerAPI.Start(shellListener.name)
	case "status":
		MessageChannel <- listenerAPI.GetListenerStatus(shellListener.id)
	case "stop":
		MessageChannel <- listenerAPI.Stop(shellListener.name)
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

// menuListeners handles all the logic for the root Listeners menu
func menuListeners(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "configure":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				return
			}

			status := listenerAPI.GetListenerStatus(id).Message
			shellListener = listener{
				id:     id,
				name:   name,
				status: status,
			}
			shellMenuContext = "listener"
			prompt.Config.AutoComplete = getCompleter("listener")
			prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m][\033[33m" + name + "\033[31m]»\033[0m ")
		} else {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Note,
				Message: "You must select a listener to configure.",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "delete":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				MessageChannel <- um
				return
			}
			if confirm(fmt.Sprintf("Are you sure you want to delete the %s listener?", name)) {
				removeMessage := listenerAPI.Remove(name)
				MessageChannel <- removeMessage
				if removeMessage.Error {
					return
				}
				shellListener = listener{}
				shellListenerOptions = nil
				shellMenuContext = "listenersmain"
				prompt.Config.AutoComplete = getCompleter("listenersmain")
				prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m]»\033[0m ")
			}
		}
	case "help", "?":
		menuHelpListenersMain()
	case "info":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			um := listenerAPI.Exists(name)
			if um.Error {
				MessageChannel <- um
				return
			}
			r, id := listenerAPI.GetListenerByName(name)
			if r.Error {
				MessageChannel <- r
				return
			}
			if id == uuid.Nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: "a nil Listener UUID was returned",
					Time:    time.Time{},
					Error:   true,
				}
			}
			oMessage, options := listenerAPI.GetListenerConfiguredOptions(id)
			if oMessage.Error {
				MessageChannel <- oMessage
				return
			}
			if options != nil {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Value"})
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				table.SetRowLine(true)
				table.SetBorder(true)

				for k, v := range options {
					table.Append([]string{k, v})
				}
				table.Render()
			}
		}
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "list":
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Name", "Interface", "Port", "Protocol", "Status", "Description"})
		table.SetAlignment(tablewriter.ALIGN_CENTER)
		listeners := listenerAPI.GetListeners()
		for _, v := range listeners {
			table.Append([]string{
				v.Name,
				v.Server.GetInterface(),
				fmt.Sprintf("%d", v.Server.GetPort()),
				servers.GetProtocol(v.Server.GetProtocol()),
				servers.GetStateString(v.Server.Status()),
				v.Description})
		}
		fmt.Println()
		table.Render()
		fmt.Println()
	case "main", "back":
		menuSetMain()
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to quit the server?") {
			exit()
		}
	case "sessions":
		menuAgent([]string{"list"})
	case "start":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			MessageChannel <- listenerAPI.Start(name)
		}
	case "stop":
		if len(cmd) >= 2 {
			name := strings.Join(cmd[1:], " ")
			MessageChannel <- listenerAPI.Stop(name)
		}
	case "use", "create":
		if len(cmd) >= 2 {
			types := listenerAPI.GetListenerTypes()
			for _, v := range types {
				if strings.ToLower(cmd[1]) == v {
					shellListenerOptions = listenerAPI.GetListenerOptions(cmd[1])
					shellListenerOptions["Protocol"] = strings.ToLower(cmd[1])
					shellMenuContext = "listenersetup"
					prompt.Config.AutoComplete = getCompleter("listenersetup")
					prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m][\033[33m" + strings.ToLower(cmd[1]) + "\033[31m]»\033[0m ")
				}
			}
		}
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

// menuListenerSetup handles all of the logic for setting up a Listener
func menuListenerSetup(cmd []string) {
	switch strings.ToLower(cmd[0]) {
	case "back":
		shellMenuContext = "listenersmain"
		prompt.Config.AutoComplete = getCompleter("listenersmain")
		prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m]»\033[0m ")
	case "help", "?":
		menuHelpListenerSetup()
	case "info", "show", "options":
		if shellListenerOptions != nil {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Value"})
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetRowLine(true)
			table.SetBorder(true)

			for k, v := range shellListenerOptions {
				table.Append([]string{k, v})
			}
			table.Render()
		}
	case "interact":
		if len(cmd) > 1 {
			i, errUUID := uuid.FromString(cmd[1])
			if errUUID != nil {
				MessageChannel <- messages.UserMessage{
					Level:   messages.Warn,
					Message: fmt.Sprintf("There was an error interacting with agent %s", cmd[1]),
					Time:    time.Now().UTC(),
					Error:   true,
				}
			} else {
				menuSetAgent(i)
			}
		}
	case "main":
		menuSetMain()
	case "quit":
		if len(cmd) > 1 {
			if strings.ToLower(cmd[1]) == "-y" {
				exit()
			}
		}
		if confirm("Are you sure you want to quit the server?") {
			exit()
		}
	case "sessions":
		menuAgent([]string{"list"})
	case "set":
		if len(cmd) >= 2 {
			for k := range shellListenerOptions {
				if cmd[1] == k {
					shellListenerOptions[k] = strings.Join(cmd[2:], " ")
					m := fmt.Sprintf("set %s to: %s", k, strings.Join(cmd[2:], " "))
					MessageChannel <- messages.UserMessage{
						Level:   messages.Success,
						Message: m,
						Time:    time.Now().UTC(),
						Error:   false,
					}
				}
			}
		}
	case "start", "run", "execute":
		um, id := listenerAPI.NewListener(shellListenerOptions)
		MessageChannel <- um
		if um.Error {
			return
		}
		if id == uuid.Nil {
			MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "a nil Listener UUID was returned",
				Time:    time.Time{},
				Error:   true,
			}
			return
		}

		shellListener = listener{id: id, name: shellListenerOptions["Name"]}
		startMessage := listenerAPI.Start(shellListener.name)
		shellListener.status = listenerAPI.GetListenerStatus(id).Message
		MessageChannel <- startMessage
		um, options := listenerAPI.GetListenerConfiguredOptions(shellListener.id)
		if um.Error {
			MessageChannel <- um
			break
		}
		shellMenuContext = "listener"
		prompt.Config.AutoComplete = getCompleter("listener")
		prompt.SetPrompt("\033[31mGandalf[\033[32mlisteners\033[31m][\033[33m" + options["Name"] + "\033[31m]»\033[0m ")
	default:
		if len(cmd) > 1 {
			executeCommand(cmd[0], cmd[1:])
		} else {
			var x []string
			executeCommand(cmd[0], x)
		}
	}
}

func menuSetModule(cmd string) {
	if len(cmd) > 0 {
		mPath := path.Join(core.CurrentDir, "data", "modules", cmd+".json")
		um, m := moduleAPI.GetModule(mPath)
		if um.Error {
			MessageChannel <- um
			return
		}
		if m.Name != "" {
			shellModule = m
			prompt.Config.AutoComplete = getCompleter("module")
			prompt.SetPrompt("\033[31mGandalf[\033[32mmodule\033[31m][\033[33m" + shellModule.Name + "\033[31m]»\033[0m ")
			shellMenuContext = "module"
		}
	}
}

func menuSetMain() {
	prompt.Config.AutoComplete = getCompleter("main")
	prompt.SetPrompt("\033[31mGandalf»\033[0m ")
	shellMenuContext = "main"
}

func getCompleter(completer string) *readline.PrefixCompleter {

	// Main Menu Completer
	var main = readline.NewPrefixCompleter(
		readline.PcItem("agent",
			readline.PcItem("list"),
			readline.PcItem("interact",
				readline.PcItemDynamic(agentListCompleter()),
			),
		),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("jobs"),
		readline.PcItem("listeners"),
		readline.PcItem("queue",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("remove",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("sessions"),
		readline.PcItem("use",
			readline.PcItem("module",
				readline.PcItemDynamic(moduleAPI.GetModuleListCompleter()),
			),
		),
		readline.PcItem("version"),
	)

	// Module Menu
	var module = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("reload"),
		readline.PcItem("run"),
		readline.PcItem("sessions"),
		readline.PcItem("show",
			readline.PcItem("options"),
			readline.PcItem("info"),
		),
		readline.PcItem("set",
			readline.PcItem("Agent",
				readline.PcItem("all"),
				readline.PcItemDynamic(agentListCompleter()),
			),
			readline.PcItemDynamic(shellModule.GetOptionsList()),
		),
		readline.PcItem("unset",
			readline.PcItemDynamic(shellModule.GetOptionsList()),
		),
	)

	// Agent Non-Windows Menu
	var agentL = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("cd"),
		readline.PcItem("clear"),
		readline.PcItem("download"),
		readline.PcItem("exec"),
		readline.PcItem("exit"),
		readline.PcItem("help"),
		readline.PcItem("ifconfig"),
		readline.PcItem("inactivemultiplier"),
		readline.PcItem("inactivethreshold"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("ipconfig"),
		readline.PcItem("ja3"),
		readline.PcItem("kill"),
		readline.PcItem("killdate"),
		readline.PcItem("jobs"),
		readline.PcItem("ls"),
		readline.PcItem("main"),
		readline.PcItem("maxretry"),
		readline.PcItem("note"),
		readline.PcItem("nslookup"),
		readline.PcItem("padding"),
		readline.PcItem("pwd"),
		readline.PcItem("quit"),
		readline.PcItem("sessions"),
		readline.PcItem("sdelete"),
		readline.PcItem("sleep"),
		readline.PcItem("status"),
		readline.PcItem("timestomp"),
		readline.PcItem("touch"),
		readline.PcItem("upload"),
	)

	// Agent Windows Menu
	var agentW = readline.NewPrefixCompleter(
		readline.PcItem("assembly"),
		readline.PcItem("back"),
		readline.PcItem("cd"),
		readline.PcItem("clear"),
		readline.PcItem("download"),
		readline.PcItem("exec"),
		readline.PcItem("execute-assembly"),
		readline.PcItem("execute-pe"),
		readline.PcItem("execute-shellcode",
			readline.PcItem("self"),
			readline.PcItem("remote"),
			readline.PcItem("RtlCreateUserThread"),
		),
		readline.PcItem("exit"),
		readline.PcItem("help"),
		readline.PcItem("ifconfig"),
		readline.PcItem("inactivemultiplier"),
		readline.PcItem("inactivethreshold"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("ipconfig"),
		readline.PcItem("ja3"),
		readline.PcItem("kill"),
		readline.PcItem("killdate"),
		readline.PcItem("jobs"),
		readline.PcItem("ls"),
		readline.PcItem("main"),
		readline.PcItem("maxretry"),
		readline.PcItem("netstat"),
		readline.PcItem("note"),
		readline.PcItem("nslookup"),
		readline.PcItem("padding"),
		readline.PcItem("pe"),
		readline.PcItem("pipes"),
		readline.PcItem("ps"),
		readline.PcItem("pwd"),
		readline.PcItem("quit"),
		readline.PcItem("sessions"),
		readline.PcItem("sdelete"),
		readline.PcItem("shinject",
			readline.PcItem("self"),
			readline.PcItem("remote"),
			readline.PcItem("RtlCreateUserThread"),
		),
		readline.PcItem("sleep"),
		readline.PcItem("status"),
		readline.PcItem("timestomp"),
		readline.PcItem("touch"),
		readline.PcItem("upload"),
		readline.PcItem("uptime"),
	)

	// Listener Menu (a specific listener)
	var listener = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("delete"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("remove"),
		readline.PcItem("restart"),
		readline.PcItem("sessions"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(shellListenerOptions["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("status"),
		readline.PcItem("stop"),
	)

	// Listeners Main Menu (the root menu)
	var listenersmain = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("configure",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("create",
			readline.PcItemDynamic(listenerAPI.GetListenerTypesCompleter()),
		),
		readline.PcItem("delete",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("help"),
		readline.PcItem("info",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("list"),
		readline.PcItem("main"),
		readline.PcItem("sessions"),
		readline.PcItem("start",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("stop",
			readline.PcItemDynamic(listenerAPI.GetListenerNamesCompleter()),
		),
		readline.PcItem("use",
			readline.PcItemDynamic(listenerAPI.GetListenerTypesCompleter()),
		),
	)

	// Listener Setup Menu
	var listenersetup = readline.NewPrefixCompleter(
		readline.PcItem("back"),
		readline.PcItem("execute"),
		readline.PcItem("help"),
		readline.PcItem("info"),
		readline.PcItem("interact",
			readline.PcItemDynamic(agentListCompleter()),
		),
		readline.PcItem("main"),
		readline.PcItem("options"),
		readline.PcItem("run"),
		readline.PcItem("sessions"),
		readline.PcItem("set",
			readline.PcItemDynamic(listenerAPI.GetListenerOptionsCompleter(shellListenerOptions["Protocol"])),
		),
		readline.PcItem("show"),
		readline.PcItem("start"),
		readline.PcItem("stop"),
	)

	switch completer {
	case "agent-nix":
		return agentL
	case "agent-windows":
		return agentW
	case "listener":
		return listener
	case "listenersmain":
		return listenersmain
	case "listenersetup":
		return listenersetup
	case "main":
		return main
	case "module":
		return module
	default:
		return main
	}
}

func menuHelpMain() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Main Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"agent", "Interact with agents or list agents", "interact, list"},
		{"banner", "Print the Gandalf banner", ""},
		{"clear", "Clear all queued commands that have not been sent to an agent", ""},
		{"jobs", "List all queued commands to unassigned agents", ""},
		{"exit", "Exit and close the Gandalf server", ""},
		{"interact", "Interact with an agent.", ""},
		{"listeners", "Move to the listeners menu", ""},
		{"queue", "Manually send a command to a client (that may not be registered yet)", "queue 2b112337-3476-4776-86fa-250b50ac8cfc sleep 300 600"},
		{"quit", "Exit and close the Gandalf server", ""},
		{"remove", "Remove or delete a DEAD agent from the server"},
		{"sessions", "List all agents session information.", ""},
		{"use", "Use a function of Gandalf", "module"},
		{"version", "Print the Gandalf server version", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
}

// The help menu while in the modules menu
func menuHelpModule() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Module Menu Help")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"info", "Show information about a module"},
		{"interact", "Interact with an agent.", ""},
		{"main", "Return to the main menu", ""},
		{"reload", "Reloads the module to a fresh clean state"},
		{"run", "Run or execute the module", ""},
		{"sessions", "List all agents session information.", ""},
		{"set", "Set the value for one of the module's options", "<option name> <option value>"},
		{"show", "Show information about a module or its options", "info, options"},
		{"unset", "Clear a module option to empty", "<option name>"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// The help menu while in the agent menu
func menuHelpAgent(platform string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Agent Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"cd", "Change directories", "cd ../../ OR cd c:\\\\Users"},
		{"clear", "Clear any UNSENT jobs from the queue", ""},
		{"download", "Download a file from the agent", "download <remote_file>"},
		{"exec", "Execute a command on the agent", "exec ping -c 3 8.8.8.8"},
		{"exit", "Instruct the agent to die", ""},
		{"help", "Display this message", ""},
		{"ifconfig", "Displays host network adapter information", ""},
		{"inactivemultiplier", "Multiply sleep values by this number each time threshold is reached", "inactivemultiplier 10"},
		{"inactivethreshold", "Go inactive if operator is idle for this many check ins", "inactivethreshold 3"},
		{"info", "Display all information about the agent", ""},
		{"interact", "Interact with an agent.", ""},
		{"ja3", "Change agent's TLS fingerprint", "github.com/Ne0nd0g/ja3transport"},
		{"jobs", "Display all active jobs for the agent", ""},
		{"kill", "Kill another process by PID", "kill <pid>"},
		{"killdate", "Set agent's killdate (UNIX epoch timestamp)", "killdate 1609480800"},
		{"ls", "List directory contents", "ls /etc OR ls C:\\\\Users OR ls C:/Users"},
		{"main", "Return to the main menu", ""},
		{"maxretry", "Set number of failed check in attempts before the agent exits", "maxretry 30"},
		{"nslookup", "Perform lookup of hostname or IP address", "nslookup 8.8.8.8"},
		{"padding", "Set maximum number of random bytes to pad messages", "padding 4096"},
		{"pwd", "Display the current working directory", "pwd"},
		{"quit", "Shutdown and close the server", ""},
		{"sessions", "List all agents session information.", ""},
		{"sdelete", "Secure delete a file", "sdelete C:\\\\Gandalf.exe"},
		{"sleep", "<min> <max> (in seconds)", "sleep 15 30"},
		{"status", "Print the current status of the agent", ""},
		{"touch", "<source> <destination>", "touch \"C:\\\\old file.txt\" C:\\\\Gandalf.exe"},
		{"upload", "Upload a file to the agent", "upload <local_file> <remote_file>"},
	}

	if platform == "windows" {
		data = append(data[:5], append([][]string{{"execute-assembly", "Execute a .NET 4.0 assembly", "execute-assembly <assembly path> [<assembly args>, <spawnto path>, <spawnto args>]"}}, data[5:]...)...)
		data = append(data[:6], append([][]string{{"execute-pe", "Execute a Windows PE (EXE)", "execute-pe <pe path> [<pe args>, <spawnto path>, <spawnto args>]"}}, data[6:]...)...)
		data = append(data[:7], append([][]string{{"execute-shellcode", "Execute shellcode", "self, remote <pid>, RtlCreateUserThread <pid>"}}, data[7:]...)...)
		data = append(data[:22], append([][]string{{"netstat", "Display network connections", "netstat -p tcp"}}, data[22:]...)...)
		data = append(data[:25], append([][]string{{"pipes", "List named pipes", ""}}, data[25:]...)...)
		data = append(data[:26], append([][]string{{"ps", "Display running processes", ""}}, data[26:]...)...)
		data = append(data[:35], append([][]string{{"uptime", "Print system uptime", ""}}, data[35:]...)...)
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
}

// The help menu for the main or root Listeners menu
func menuHelpListenersMain() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listeners Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the main menu", ""},
		{"configure", "Configure existing listener", "configure <listener_name>"},
		{"create", "Create a new listener by protocol type", "create [http,https,http2,http3,h2c]"},
		{"delete", "Delete a named listener", "delete <listener_name>"},
		{"info", "Display all information about a listener", "info <listener_name>"},
		{"interact", "Interact with an agent.", ""},
		{"list", "List all created listeners", ""},
		{"main", "Return to the main menu", ""},
		{"sessions", "List all agents session information.", ""},
		{"start", "Start a named listener", "start <listener_name>"},
		{"stop", "Stop a named listener", "stop <listener_name>"},
		{"use", "Create a new listener by protocol type", "use [http,https,http2,http3,h2c]"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
}

// The help menu for Listeners template, or setup, menu
func menuHelpListenerSetup() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Setup Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"execute", "Create and start the listener (alias)", ""},
		{"info", "Display all configurable information about a listener", ""},
		{"interact", "Interact with an agent.", ""},
		{"main", "Return to the main menu", ""},
		{"options", "Display all configurable information about a listener", ""},
		{"run", "Create and start the listener (alias)", ""},
		{"sessions", "List all agents session information.", ""},
		{"set", "Set a configurable option", "set <option_name>"},
		{"show", "Display all configurable information about a listener", ""},
		{"start", "Create and start the listener", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
}

// The help menu for a specific, instantiated, listener
func menuHelpListener() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Listener Help Menu")
	table.SetHeader([]string{"Command", "Description", "Options"})

	data := [][]string{
		{"back", "Return to the listeners menu", ""},
		{"delete", "Delete this listener", "delete <listener_name>"},
		{"info", "Display all configurable information the current listener", ""},
		{"interact", "Interact with an agent.", ""},
		{"main", "Return to the main menu", ""},
		{"restart", "Restart this listener", ""},
		{"sessions", "List all agents session information.", ""},
		{"set", "Set a configurable option", "set <option_name>"},
		{"show", "Display all configurable information about a listener", ""},
		{"start", "Start this listener", ""},
		{"status", "Get the server's current status", ""},
		{"stop", "Stop the listener", ""},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func displayJobTable(rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"Agent ID", "Command", "Status"})

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// displayTable writes arbitrary data rows to STDOUT
func displayTable(header []string, rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)

	if len(header) > 0 {
		table.SetHeader(header)
	}

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// confirm reads in a string and returns true if the string is y or yes but does not provide the prompt question
func confirm(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	//fmt.Print(color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)))
	MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)),
		Time:    time.Now().UTC(),
		Error:   false,
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error reading the input:\r\n%s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes", "-y", "-Y"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}
	return false
}

// quit will prompt the user to confirm if they want to exit
func exit() {
	color.Red("[!]Quitting...")
	logging.Server("Shutting down Gandalf due to user input")
	os.Exit(0)
}

func executeCommand(name string, arg []string) {
	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Unknown command",
		Time:    time.Time{},
		Error:   false,
	}
}

func registerMessageChannel() {
	um := messages.Register(clientID)
	if um.Error {
		MessageChannel <- um
		return
	}
	if core.Debug {
		MessageChannel <- um
	}
}

func getUserMessages() {
	go func() {
		for {
			MessageChannel <- messages.GetMessageForClient(clientID)
		}
	}()
}

// printUserMessage is used to print all messages to STDOUT for command line clients
func printUserMessage() {
	go func() {
		for {
			m := <-MessageChannel
			switch m.Level {
			case messages.Info:
				fmt.Println(color.CyanString("\n[i] %s", m.Message))
			case messages.Note:
				fmt.Println(color.YellowString("\n[-] %s", m.Message))
			case messages.Warn:
				fmt.Println(color.RedString("\n[!] %s", m.Message))
			case messages.Debug:
				if core.Debug {
					fmt.Println(color.RedString("\n[DEBUG] %s", m.Message))
				}
			case messages.Success:
				fmt.Println(color.GreenString("\n[+] %s", m.Message))
			case messages.Plain:
				fmt.Println("\n" + m.Message)
			default:
				fmt.Println(color.RedString("\n[_-_] Invalid message level: %d\r\n%s", m.Level, m.Message))
			}
		}
	}()
}

// agentListCompleter returns a list of agents that exist and is used for command line tab completion
func agentListCompleter() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		agentList := agentAPI.GetAgents()
		for _, id := range agentList {
			a = append(a, id.String())
		}
		return a
	}
}

type listener struct {
	id     uuid.UUID // Listener unique identifier
	name   string    // Listener unique name
	status string    // Listener server status
}
