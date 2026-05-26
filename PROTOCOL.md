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

The nicknames `__SERVER__` and `__MOTD__` are reserved and will be rejected with `INV`. If the nick is already logged in, the server also responds with `INV`.

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

## Commands

All commands are sent as a single newline-terminated line. The server responds with `ACK` on success or `INV` on failure unless otherwise noted.

| Command | Format | Permission | Description |
|---------|--------|------------|-------------|
| STS | `STS` | any | Request own status. Server replies with a MSG from `__SERVER__` containing nick and admin flag. |
| LST | `LST` | any | List online users. Server replies with a MSG from `__SERVER__` listing one nick per line. |
| MSG | `MSG <length>` | any | Send a chat message (see above). |
| SAY | `SAY <nick> <length>` | any | Send a direct message (see above). |
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
| `INV` | Invalid request or permission denied |
| `KCK` | You have been kicked |
| `BYE` | Server shutdown |
| `MSG <origin> <length>` | Incoming broadcast message (see above) |
| `SAY <origin> <length>` | Incoming direct message (see above) |

## Unknown Commands

Any unrecognized command causes the server to reply with `INV` and close the connection.
