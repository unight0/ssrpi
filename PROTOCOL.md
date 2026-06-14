# SSRP — Simplest Secure chatRoom Protocol

SSRP runs over TLS/TCP. All control messages are newline-terminated (`\n`). The default port is **8666**.

## Connection Handshake

```
Server → Client:  PWD
Client → Server:  <server password>
Server → Client:  ACK | INV
```

If `INV`, the connection is closed. If `ACK`, the server continues:

```
Server → Client:  NCK
Client → Server:  <nickname>
```

Nicknames may only contain letters, numbers, underscores, and hyphens. The nicknames `__SERVER__` and `__MOTD__` are reserved. Invalid nicks are rejected with `INV FORBIDDEN-CHAR`, reserved nicks with `INV RESERVED-NICK`, and already-online nicks with `INV ALREADY-LOGGED-IN`.

### User Authentication

If the nick is registered, the server requests the user password:

```
Server → Client:  PWD
Client → Server:  <user password>
Server → Client:  ACK | INV
```

If the nick is new, the server requests a password to register with:

```
Server → Client:  NPW
Client → Server:  <new password>
Server → Client:  ACK
```

Passwords are stored as SHA-256 hashes. The first user to register is automatically made admin.

### Post-Login

After successful authentication, the server sends the MOTD (if configured) as a `MSG` from `__MOTD__`.

## Messages

### MSG (Chat Message)

Client to server:

```
MSG <length>\n
<body>
```

Server to client (broadcast / server messages):

```
MSG <origin> <length>\n
<body>
```

`<origin>` is the sender's nick, `__SERVER__`, or `__MOTD__`. `<length>` is the byte length of `<body>`. The body is **not** newline-terminated; the reader must consume exactly `<length>` bytes.

Messages are broadcast to all connected clients except the sender.

### SAY (Direct Message)

Client to server:

```
SAY <recipient> <length>\n
<body>
```

Server to recipient:

```
SAY <origin> <length>\n
<body>
```

Same framing as MSG. The server delivers the message only to the named recipient. If the recipient is not online, the server responds with `INV`. Otherwise, the sender receives `ACK`.

### UPL (Upload Resource)

Client to server:

```
UPL <alias> <recipients> <size>\n
<binary data>
```

`<id>` is a client-chosen identifier (typically the filename), used as an alias. `<recipients>` is a comma-separated list of nicks (e.g. `alice,bob`) or `*` for all connected clients. `<size>` is the byte length of the data that follows. The server stores the resource in memory (backed by a temp file), assigns it a UUID, replies with `ACK`, then notifies the specified recipients:

```
UPL <origin> <alias> <uuid> <size>\n
```

This notification is header-only (no body). The `<alias>` is the original `<id>` from the uploader. The `<uuid>` is the server-assigned identifier used for GET requests. Only listed recipients can retrieve the resource.

### GET (Download Resource)

Client to server:

```
GET <uuid>\n
```

If the resource exists and the requesting user is in the recipient list, the server responds:

```
GET <uuid> <size>\n
<binary data>
```

If the resource does not exist, or the requesting user is not in the recipient list, the server responds with `INV NO-SUCH-RESOURCE`.

## Commands

All commands are sent as a single newline-terminated line. The server responds with `ACK` on success, `INV <reason>` on client error, or `ERR` on server-side error unless otherwise noted.

| Command | Format | Permission | Description |
|---------|--------|------------|-------------|
| STS | `STS` | any | Request own status. Server replies with a MSG from `__SERVER__` containing nick and admin flag. |
| LST | `LST` | any | List online users. Server replies with a MSG from `__SERVER__` listing one nick per line. |
| MSG | `MSG <length>` | any | Send a chat message (see above). |
| SAY | `SAY <nick> <length>` | any | Send a direct message (see above). |
| UPL | `UPL <alias> <recipients> <size>` | any | Upload a resource (see above). |
| GET | `GET <uuid>` | any | Download a resource (see above). |
| NPW | `NPW <newpass>` | any | Change own password. |
| SPW | `SPW <newpass>` | admin | Set the server password. |
| ADM | `ADM <nick> <0\|1>` | admin | Grant (1) or revoke (0) admin on a user. |
| KCK | `KCK <nick>` | admin | Kick a user. The target receives `KCK` before disconnection. |
| SHT | `SHT` | admin | Shut down the server. `BYE` sent out by the server to all clients .|
| BYE | `BYE` | any | Graceful disconnect. Server replies with ACK. |

## Server-Initiated Messages

| Message | Meaning |
|---------|---------|
| `ACK` | Success / acknowledgement |
| `INV <reason>` | Invalid request or permission denied. Reason codes: `WRONG-PASSWORD`, `WRONG-SERVER-PASSWORD`, `RESERVED-NICK`, `FORBIDDEN-CHAR`, `ALREADY-LOGGED-IN`, `NO-SUCH-USER`, `NO-SUCH-RESOURCE`, `NO-PRIVILEGES`, `MALFORMED`, `UNKNOWN` |
| `ERR` | Internal server error |
| `KCK` | You have been kicked |
| `BYE` | Server shutdown |
| `MSG <origin> <length>` | Incoming broadcast message (see above) |
| `SAY <origin> <length>` | Incoming direct message (see above) |
| `UPL <origin> <alias> <uuid> <size>` | A user uploaded a resource (header-only notification) |
| `GET <uuid> <size>` | Resource data in response to a GET request |

## Unknown Commands

Any unrecognized command causes the server to reply with `INV UNKNOWN` and close the connection.
