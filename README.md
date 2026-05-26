# EVE Forward Auth
***

This project provides forward authentication for eve online. It has minimal real interaction with the service itself. Instead, it is designed to communicate with your proxy (nginx, caddy, traefik, etc.) and decide whether or not the proxy allows you through. It is completely transparent to the web service behind the proxy.

To install:
- Clone the repo
- Install go dependencies
- Populate `config.toml` (a `.example` version is given here)
- Configure your proxy to use this server for auth (an example caddyfile is provided)
- Start the server with `go run main.go version.go`
- Enjoy!
