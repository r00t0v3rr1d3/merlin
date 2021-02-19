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

package main

import (
	// Standard
	"flag"
	"os"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli"
	"github.com/Ne0nd0g/merlin/pkg/logging"
)

// Global Variables
var build = "nonRelease"

func main() {
	logging.Server("Starting Gandalf Server version " + merlin.Version + " build " + merlin.Build)

	flag.Usage = func() {
		color.White("#################################################")
		color.White("#\t\tGANDALF SERVER\t\t\t#")
		color.White("#################################################")
		color.White("Version: " + merlin.Version)
		color.White("Build: " + build)
		color.White("Codename: Gandalf")
		color.Yellow("Gandalf Server does not take any command line arguments")
		flag.PrintDefaults()
		os.Exit(0)
	}
    ip := flag.String("pwn", "", "The IP address / hostname of pwnboard server")

	flag.Parse()

	color.White(banner.MerlinBanner2)
	color.White("\t\t   Version: %s", merlin.Version)
	color.White("\t\t   Build: %s", build)
	color.White("\t\t   Codename: Gandalf")

    if *ip != ""{
        go pwnboard.Updateserver(*ip)
    }

	// Start Merlin Command Line Interface
	cli.Shell()
}
