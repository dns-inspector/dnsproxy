# dnsproxy

dnsproxy is a server that proxies DNS over TLS and DNS over HTTPS requests to a standard DNS server.

## Usage

dnsproxy is intended to directly face the internet, and should be run as root to allow it to bind to
the appropriate ports (443, 853). dnsproxy requires a TLS certificate and private key.

```
Usage dnsproxy [options]

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
```

## License

dnsproxy is free and open source software governed by the terms of the GNU General Public License
v3.
