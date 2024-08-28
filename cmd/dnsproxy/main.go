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
	"strconv"
	"syscall"

	"dnsproxy"
)

func printHelpAndExit() {
	fmt.Printf(`Usage %s [options]

Options:
-c --certificate <value>   Specify the path to server certificate. Multiple certificates can be
                           included to form a chain, with the leaf as the first. Certificates must
                           be PEM encoded, without encryption.
                           Default is 'server.crt'

-k --key <value>           Specify the path to the private key. The key must be a PEM-encoded PKCS#1
                           RSA or ECDSA private key.
                           Default is 'server.key'

-s --server <value>        Specify the IPv4 address with port to proxy DNS requests to. Proxied
                           requests always use DNS over TCP.
                           Default is '127.0.0.1:53'

-l --log-file <value>      Specify the path to the log file to write to.
                           Default is 'dnsproxy.log'

--https-port <value>       Specify the port used for the DNS over HTTPS server.
                           Defaults is 443

--tls-port <value>         Specify the port used for the DNS over TLS server.
                           Defaults is 853
`, os.Args[0])
	os.Exit(1)
}

func main() {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		if arg == "-c" || arg == "--certificate" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			dnsproxy.CertPath = os.Args[i+1]
			i++
		} else if arg == "-k" || arg == "--key" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			dnsproxy.KeyPath = os.Args[i+1]
			i++
		} else if arg == "-s" || arg == "--server" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			dnsproxy.DNSServerAddr = os.Args[i+1]
			i++
		} else if arg == "-l" || arg == "--log-file" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			dnsproxy.LogPath = os.Args[i+1]
			i++
		} else if arg == "--https-port" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			if _, err := strconv.ParseUint(os.Args[i+1], 10, 16); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid value for %s\n", arg)
				printHelpAndExit()
			}
			dnsproxy.HTTPSPort = os.Args[i+1]
			i++
		} else if arg == "--tls-port" {
			if i == len(os.Args)-1 {
				fmt.Fprintf(os.Stderr, "Argument %s requires a parameters\n", arg)
				printHelpAndExit()
			}
			if _, err := strconv.ParseUint(os.Args[i+1], 10, 16); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid value for %s\n", arg)
				printHelpAndExit()
			}
			dnsproxy.TLSPort = os.Args[i+1]
			i++
		} else if arg == "-v" || arg == "--version" {
			fmt.Printf("%s (Variant: %s-%s, Built on: %s, Revision: %s)\n", dnsproxy.Version, runtime.GOOS, runtime.GOARCH, dnsproxy.BuiltOn, dnsproxy.Revision)
			os.Exit(0)
		} else {
			fmt.Fprintf(os.Stderr, "Unknown argument %s\n", arg)
			printHelpAndExit()
		}
	}

	halt := make(chan os.Signal, 1)
	signal.Notify(halt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-halt
		dnsproxy.Stop()
		os.Exit(1)
	}()

	rotate := make(chan os.Signal, 1)
	signal.Notify(rotate, syscall.SIGUSR1)
	go func() {
		<-rotate
		dnsproxy.RotateLog()
	}()

	dnsproxy.Start()
	dnsproxy.Stop()
}
