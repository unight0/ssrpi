# SSRPI

Simplest Secure chatRoom Protocol Implementation — a lightweight TLS-encrypted chat system written in Go.

## Overview

SSRPI is a client-server chat application that communicates over TLS. It features user registration and authentication, admin controls (kick, promote, server password management, remote shutdown), MOTD support, and message broadcasting. See [PROTOCOL.md](PROTOCOL.md) for the wire protocol specification.

The overarching goal of this _pet project_ is to create a chatroom protocol that
is simultaneously very simple to implement yet provides decent security.

## Building

Requires Go 1.21+ and CGO (for SQLite).

```sh
# Server
cd serv && go build -o ssrpi-serv

# Client
cd client && go build -o ssrpi-client
```

## Server

The server requires a TLS certificate and key pair. A helper script is included:

```sh
cd serv
./makecert.sh
```

### Usage

```
ssrpi-serv [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8666` | Listening port |
| `-db` | `./users.db` | SQLite database path |
| `-cert` | `./cert.pem` | TLS certificate |
| `-key` | `./key.pem` | TLS private key |
| `-motd` | *(none)* | Path to a text file displayed on login |

The default server password is `default_password` — change it with an admin client after first login.

The first user to register is automatically granted admin privileges.

## Client

The client uses a TUI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea). Connection details can be provided via flags or entered interactively.

### Usage

```
ssrpi-client [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(interactive)* | Server address (`host:port`) |
| `-servpass` | *(interactive)* | Server password |
| `-nick` | *(interactive)* | Nickname |
| `-pass` | *(interactive)* | User password |

### Chat Commands

| Command | Description |
|---------|-------------|
| `/status` (`/s`) | Show your nick and admin status |
| `/list` (`/l`) | List online users |
| `/say` (`/dm`) `<nick> <msg>` | Send a direct message |
| `/upload` (`/upl`) `<file>` | Upload a file to the server |
| `/get <id>` | Download a file from the server |
| `/kick` (`/k`) `<nick>` | Kick a user (admin) |
| `/admin <nick> <0\|1>` | Grant or revoke admin (admin) |
| `/password` (`/pw`) `<pw>` | Change your password |
| `/setpass <pw>` | Set the server password (admin) |
| `/shutdown` | Shut down the server (admin) |
| `/quit` (`/q`) | Disconnect and exit |
