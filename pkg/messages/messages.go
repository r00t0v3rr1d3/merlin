// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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

package messages

import (
	"crypto/rsa"
	"encoding/gob"

	uuid "github.com/satori/go.uuid"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register(AgentControl{})
	gob.Register(AgentInfo{})
	gob.Register(CmdPayload{})
	gob.Register(WinExecute{})
	gob.Register(CmdResults{})
	gob.Register(FileTransfer{})
	gob.Register(KeyExchange{})
	gob.Register(Module{})
	gob.Register(NativeCmd{})
	gob.Register(TouchFile{})
	gob.Register(Shellcode{})
	gob.Register(SysInfo{})
}

// Base is the base JSON Object for HTTP POST payloads
type Base struct {
	Version float32     `json:"version"`
	ID      uuid.UUID   `json:"id"`
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
	Padding string      `json:"padding"`
	Token   string      `json:"token,omitempty"`
}

// FileTransfer is the JSON payload to transfer files between the server and agent
type FileTransfer struct {
	FileLocation string `json:"dest"`
	FileBlob     string `json:"blob"`
	IsDownload   bool   `json:"download"`
	Job          string `json:"job"`
}

// CmdPayload is the JSON payload for commands to execute on an agent
type CmdPayload struct {
	Command string `json:"executable"`
	Args    string `json:"args"`
	Job     string `json:"job"`
}

// ExecuteCommand is a JSON payload for commands to execute using the native Windows API
type WinExecute struct {
	Command string `json:"executable"`
	Ppid    int    `json:"ppid"`
	Args    string `json:"args"`
	Job     string `json:"job"`
}

// SysInfo is a JSON payload containing information about the system where the agent is running
type SysInfo struct {
	Platform     string   `json:"platform,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	UserName     string   `json:"username,omitempty"`
	UserGUID     string   `json:"userguid,omitempty"`
	HostName     string   `json:"hostname,omitempty"`
	Pid          int      `json:"pid,omitempty"`
	Process      string   `json:"process,omitempty"`
	Ips          []string `json:"ips,omitempty"`
}

// CmdResults is a JSON payload that contains the results of an executed command from an agent
type CmdResults struct {
	Job     string `json:"job"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
	Padding string `json:"padding"` // Padding to help evade detection
}

// AgentControl is a JSON payload to send control messages to the agent (i.e. kill or die)
type AgentControl struct {
	Job     string `json:"job"`
	Command string `json:"command"`
	Args    string `json:"args,omitempty"`
	Result  string `json:"result"`
}

// AgentInfo is a JSON payload containing information about the agent and its configuration
type AgentInfo struct {
	Version            string  `json:"version,omitempty"`
	Build              string  `json:"build,omitempty"`
	WaitTimeMin        int64   `json:"waittimemin,omitempty"`
	WaitTimeMax        int64   `json:"waittimemax,omitempty"`
	ActiveMin          int64   `json:"activemin,omitempty"`
	ActiveMax          int64   `json:"activemax,omitempty"`
	InactiveMultiplier int64   `json:"inactivemultipler,omitempty"`
	InactiveThreshold  int     `json:"inactivethreshold,omitempty"`
	PaddingMax         int     `json:"paddingmax,omitempty"`
	MaxRetry           int     `json:"maxretry,omitempty"`
	FailedCheckin      int     `json:"failedcheckin,omitempty"`
	Proto              string  `json:"proto,omitempty"`
	SysInfo            SysInfo `json:"sysinfo,omitempty"`
	KillDate           int64   `json:"killdate,omitempty"`
	JA3                string  `json:"ja3,omitempty"`
}

// Shellcode is a JSON payload containing shellcode and the method for execution
type Shellcode struct {
	Method string `json:"method"`
	Bytes  string `json:"bytes"` // Base64 string of shellcode bytes
	Job    string `json:"job"`
	PID    uint32 `json:"pid,omitempty"` // Process ID for remote injection
}

// Module is a JSON payload used to send module directives.
type Module struct {
	Job     string   `json:"job"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Result  string   `json:"result"`
}

// NativeCmd is a JSON payload to execute commands native inside of Merlin using go instead of executing the binary
// program on the host (i.e. ls)
type NativeCmd struct {
	Job     string `json:"job"`
	Command string `json:"command"`
	Args    string `json:"args,omitempty"`
}

// TouchFile is a simple job like NativeCmd but can't have space-separated args
type TouchFile struct {
	Job     string `json:"job"`
	Command string `json:"command"`
	SrcFile string `json:"srcfile,omitempty"`
	DstFile string `json:"dstfile,omitempty"`
}

// KeyExchange is a JSON payload used to exchange public keys for encryption
type KeyExchange struct {
	PublicKey rsa.PublicKey `json:"publickey"`
}
