/*
DNSProxy
Copyright (C) 2024 Ian Spence

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"dnsproxy"
)

func printHelpAndExit() {
	fmt.Printf(`Usage %s <mode> [options]

Modes:
config     Print out the default configuration to stdout and exit
server     Start the dnsproxy server
test       Validate the dnsproxy configuration. Print any errors to stderr. Exits with 0 if valid.

Options:
-c --config <value>      Specify the path to the config file. Only used in server and test mode.

Signals:
USR1       Rotate the log file by appending yesterdays date to the file name and start a new file
USR2       Reload the configuration without restarting the process
`, os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) == 1 {
		printHelpAndExit()
	}

	testOnly := false

	verb := os.Args[1]
	switch verb {
	case "config":
		fmt.Print(dnsproxy.DefaultConfig)
		os.Exit(0)
	case "server":
		testOnly = false
	case "test":
		testOnly = true
	case "-v", "--version":
		fmt.Printf("%s (Variant: %s-%s, Built on: %s, Revision: %s)\n", dnsproxy.Version, runtime.GOOS, runtime.GOARCH, dnsproxy.BuiltOn, dnsproxy.Revision)
		os.Exit(0)
	case "-h", "--help":
		printHelpAndExit()
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode %s\n", verb)
		printHelpAndExit()
	}

	configPath := "/etc/dnsproxy/dnsproxy.conf"

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]

		if arg == "-c" || arg == "--config" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			configPath = os.Args[i+1]
			i++
		} else {
			fmt.Fprintf(os.Stderr, "Unknown argument %s\n", arg)
			printHelpAndExit()
		}
	}

	if testOnly {
		dnsproxy.TestConfig(configPath)
		fmt.Println("dnsproxy configuration is valid")
		os.Exit(0)
	}

	halt := make(chan os.Signal, 1)
	signal.Notify(halt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-halt
		dnsproxy.Stop(false)
		os.Exit(1)
	}()

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGUSR2)
	go func() {
		for {
			<-reload
			dnsproxy.Stop(true)
		}
	}()

	rotate := make(chan os.Signal, 1)
	signal.Notify(rotate, syscall.SIGUSR1)
	go func() {
		for {
			<-rotate
			dnsproxy.RotateLog()
		}
	}()

	for {
		shouldRestart, err := dnsproxy.Start(configPath)
		if !shouldRestart {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
	}
}
