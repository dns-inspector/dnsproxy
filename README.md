# dnsproxy

dnsproxy is a server that proxies DNS over TLS and DNS over HTTPS requests to a standard DNS server.

## Usage

dnsproxy is intended to directly face the internet, and should be run as root to allow it to bind to
the appropriate ports (443, 853). dnsproxy requires a TLS certificate and private key.

```
Usage dnsproxy <mode> [options]

Modes:
config     Print out the default configuration to stdout and exit
server     Start the dnsproxy server
test       Validate the dnsproxy configuration. Print any errors to stderr. Exits with 0 if valid.

Options:
-c --config <value>      Specify the path to the config file. Only used in server and test mode.

Signals:
USR1       Rotate the log file by appending yesterdays date to the file name and start a new file
USR2       Reload the configuration without restarting the process
```

### Configuration

dnsproxy is configured using a configuration file. To generate a default configuration file, run
`dnsproxy config`

### Monitoring

dnsproxy can act as a Zabbix agent. When the `zabbix_server` configuration proerty is set, it will
send the following metrics every minute:

|Item Key|Description|
|-|-|
|`agent.ping`|Will always be `1` so long as dnsproxy is running.|
|`panic.recover`|The number of panics that have been recovered from within the last minute.|
|`query.doh.forward`|The number of DNS over HTTPS queries that have been forwarded.|
|`query.dot.forward`|The number of DNS over TLS queries that have been forwarded.|
|`query.doh.error`|The number of DNS over HTTPS queries that failed.|
|`query.dot.error`|The number of DNS over TLS queries that failed.|

## License

dnsproxy is free and open source software governed by the terms of the GNU General Public License
v3.
