package main

import (
	"os"
	"errors"
	"fmt"
	"time"
	"io"
	"flag"
	"bufio"
	"net"
	"log"
	"sync"
	"crypto/tls"
	"crypto/sha256"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var ErrPerm = errors.New("Action not allowed")
var ErrNoUser = errors.New("User doesn't exist")

var db *sql.DB
var dbLock sync.Mutex

// Active Client
type aClient struct {
	nick string
	rw *bufio.ReadWriter
}

var clients []aClient
var clientsLock sync.Mutex

// Queued Message
type qMessage struct {
	origin string
	content []byte
}

var messageQueue []qMessage
var messageQueueLock sync.Mutex

var motdFilepath string

func isClientActive(nick string) bool {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	for _, c := range clients {
		if c.nick == nick {
			return true
		}
	}

	return false
}

func addActiveClient(nick string, rw *bufio.ReadWriter) {
	clientsLock.Lock()
	clients = append(clients, aClient{nick, rw})
	clientsLock.Unlock()
}

func delActiveClient(nick string) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	var i int
	var e aClient
	for i, e = range clients {
		if e.nick == nick {
			break
		}
	}
	// No such client
	if e.nick != nick {
		return
	}

	clients[i] = clients[len(clients) - 1]
	clients = clients[:len(clients) - 1]
}

func userExists(nick string) bool {
	var exists bool

	dbLock.Lock()
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE nick = ?)", nick).Scan(&exists)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return exists
}

func userPassword(nick string) [sha256.Size]byte {
	var passhash []byte

	dbLock.Lock()
	err := db.QueryRow("SELECT passhash FROM users WHERE nick = ?", nick).Scan(&passhash)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return [sha256.Size]byte(passhash)
}

func isUserAdmin(nick string) bool {
	var isAdmin bool 

	dbLock.Lock()
	err := db.QueryRow("SELECT isAdmin FROM users WHERE nick = ?", nick).Scan(&isAdmin)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return isAdmin
}

func countUsers() uint {
	var count uint

	dbLock.Lock()
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return count
}

func registerUser(nick string, passhash [sha256.Size]byte) {
	isAdmin := countUsers() == 0

	dbLock.Lock()
	_, err := db.Exec(
		"INSERT INTO users (nick, passhash, isAdmin) VALUES (?, ?, ?)",
		nick,
		passhash[:],
		isAdmin,
	)
	dbLock.Unlock()

	checkFatal(err, "db.Exec()")
}

func makeUserAdmin(nick string, value bool) {

	dbLock.Lock()
	_, err := db.Exec(
		"UPDATE users SET isAdmin = ? WHERE nick = ?",
		value,
		nick,
	)
	dbLock.Unlock()

	checkFatal(err, "db.Exec()")
}

func getServerPassword() string {
	var pass string

	dbLock.Lock()
	err := db.QueryRow("SELECT value FROM config WHERE key = ?", "serverPassword").Scan(&pass)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return pass
}

func setServerPassword(pass string) {
	dbLock.Lock()
	_, err := db.Exec("UPDATE config SET value = ? WHERE key = ?", pass, "serverPassword")
	dbLock.Unlock()

	checkFatal(err, "db.Exec()")
}

func setUserPassword(nick string, passhash [sha256.Size]byte) {
	dbLock.Lock()
	_, err := db.Exec("UPDATE users SET passhash = ? WHERE nick = ?", passhash[:], nick)
	dbLock.Unlock()

	checkFatal(err, "db.Exec()")
}

func connLogin(rw *bufio.ReadWriter, nick string) bool {
	_, err := rw.WriteString("PWD\n")
	rw.Flush()

	if err != nil {
		log.Printf("rw.Write(): %v\n", err)
		return false
	}

	passwd, _, err := rw.ReadLine()

	if err != nil {
		log.Printf("rw.ReadLine(): %v\n", err)
		return false
	}

	passwdHash := sha256.Sum256(passwd)
	correctHash := userPassword(nick)

	if passwdHash != correctHash {
		serveInvalid(rw)

		log.Printf("Invalid password for %v\n", nick)
		return false
	}

	serveAck(rw)

	log.Printf("%v logged in\n", nick)

	return true
}

func connReg(rw *bufio.ReadWriter, nick string) bool {
	_, err := rw.Write([]byte("NPW\n"))
	rw.Flush()

	if err != nil {
		log.Printf("rw.Write(): %v\n", err)
		return false
	}

	passwd, _, err := rw.ReadLine()

	if err != nil {
		log.Printf("rw.ReadLine(): %v\n", err)
		return false
	}

	passwdHash := sha256.Sum256(passwd)

	registerUser(nick, passwdHash)

	serveAck(rw)

	log.Printf("Registered %v\n", nick)

	return true
}

func sendMessage(rw *bufio.ReadWriter, origin string, msg []byte) (int, error) {
	return fmt.Fprintf(rw, "MSG %s %d\n%s", origin, len(msg), msg)
}

func serveStatus(rw *bufio.ReadWriter, nick string) (n int, err error) {
	isAdmin := isUserAdmin(nick)

	n, err = sendMessage(rw, "__SERVER__",
		[]byte(fmt.Sprintf("STATUS\nNICK: %s\nADMIN: %t\n",
					 nick,
					 isAdmin)))
	rw.Flush()
	return
}

func serveList(rw *bufio.ReadWriter) (n int, err error) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	var message string

	for _, e := range clients {
		message += fmt.Sprintf("%s\n", e.nick)
	}

	n, err = sendMessage(rw, "__SERVER__", []byte(message))
	rw.Flush()
	return
}

func serveInvalid(rw *bufio.ReadWriter) {
	rw.Write([]byte("INV\n"))
	rw.Flush()
}

func serveAck(rw *bufio.ReadWriter) {
	rw.Write([]byte("ACK\n"))
	rw.Flush()
}

func serveMotd(rw *bufio.ReadWriter) (n int, err error) {
	if motdFilepath == "" {
		return 0, nil
	}

	motd, err := os.ReadFile(motdFilepath)

	n, err = sendMessage(rw, "__MOTD__", motd)
	rw.Flush()
	return
}

func serveMsg(rw *bufio.ReadWriter, nick string, header string) error {
	var msgLen uint

	_, err := fmt.Sscanf(header, "MSG %d", &msgLen)

	if err != nil {
		serveInvalid(rw)
		return err
	}

	msg := make([]byte, msgLen)

	_, err = io.ReadFull(rw, msg)

	if err != nil {
		serveInvalid(rw)
		return err
	}

	messageQueueLock.Lock()
	messageQueue = append(messageQueue, qMessage {nick, msg})
	messageQueueLock.Unlock()

	serveAck(rw)

	return nil
}

func broadcaster() {
	for {
		time.Sleep(time.Second)
		var message qMessage
		messageQueueLock.Lock()

		if len(messageQueue) == 0 {
			messageQueueLock.Unlock()
			continue
		}

		message = messageQueue[0]
		messageQueue = messageQueue[1:]

		messageQueueLock.Unlock()

		log.Printf("Broadcasting '%s'\n", message.content)

		clientsLock.Lock()

		for _, c := range clients {
			if c.nick == message.origin {
				continue
			}

			_, err := sendMessage(c.rw, message.origin, message.content)
			c.rw.Flush()

			if err != nil {
				log.Printf("sendMessage(): %v\n", err)
			}
		}

		clientsLock.Unlock()
	}
}

func serveMakeAdmin(rw *bufio.ReadWriter, nick string, request string) error {
	var whom string
	var valu int
 
	_, err := fmt.Sscanf(request, "ADM %s %d", &whom, &valu)

	val := valu != 0

	if err != nil {
		serveInvalid(rw)
		return err
	}

	if !userExists(whom) {
		serveInvalid(rw)
		return ErrNoUser
	}

	can := isUserAdmin(nick)

	if !can {
		serveInvalid(rw)
		return ErrPerm
	}

	makeUserAdmin(whom, val)
	serveAck(rw)

	return nil
}

func kick(nick string) error {
	if !userExists(nick) {
		return ErrNoUser
	}

	clientsLock.Lock()
	for _, c := range clients {
		if c.nick == nick {
			c.rw.WriteString("KCK\n")
			c.rw.Flush()
			break
		}
	}
	clientsLock.Unlock()

	delActiveClient(nick)

	return nil
}

func serveKick(rw *bufio.ReadWriter, nick string, request string) (err error) {
	var whom string

	_, err = fmt.Sscanf(request, "KCK %s", &whom)

	if err != nil {
		serveInvalid(rw)
		return err
	}

	if !isUserAdmin(nick) {
		serveInvalid(rw)
		return ErrPerm
	}

	if !userExists(whom) {
		serveInvalid(rw)
		return ErrNoUser
	}

	err = kick(whom)
	serveAck(rw)

	return nil
}

func serveShutdown(rw *bufio.ReadWriter, nick string) (err error) {
	if !isUserAdmin(nick) {
		serveInvalid(rw)
		return ErrPerm
	}

	serveAck(rw)

	log.Printf("%s initiated shutdown...\n", nick)

	clientsLock.Lock()
	for _, c := range clients {
		c.rw.WriteString("BYE\n")
		c.rw.Flush()
	}
	clientsLock.Unlock()

	os.Exit(0)

	return nil
}

func serveSetServerPassword(rw *bufio.ReadWriter, nick string, request string) error {
	var newpass string

	_, err := fmt.Sscanf(request, "SPW %s", &newpass)

	if err != nil {
		serveInvalid(rw)
		return err
	}

	can := isUserAdmin(nick)

	if !can {
		serveInvalid(rw)
		return ErrPerm
	}

	setServerPassword(newpass)
	serveAck(rw)

	return nil
}

func serveNewPassword(rw *bufio.ReadWriter, nick string, request string) error {
	var newpass string

	_, err := fmt.Sscanf(request, "NPW %s", &newpass)

	if err != nil {
		serveInvalid(rw)
		return err
	}

	passhash := sha256.Sum256([]byte(newpass))

	setUserPassword(nick, passhash)
	serveAck(rw)

	return nil
}

func serveClient(conn net.Conn) {
	defer conn.Close()

	rw := bufio.NewReadWriter(
		bufio.NewReader(conn),
		bufio.NewWriter(conn),
	)

	_, err := rw.Write([]byte("PWD\n"))
	rw.Flush()

	if err != nil {
		log.Printf("rw.Write(): %v\n", err)
		return
	}

	passwd, _, err := rw.ReadLine()

	if err != nil {
		log.Printf("rw.ReadLine(): %v\n", err)
		return
	}

	passwdHash := sha256.Sum256(passwd)

	correctHash := sha256.Sum256([]byte(getServerPassword()))

	if passwdHash != correctHash {
		log.Printf("Invalid password provided by %v\n", conn.RemoteAddr())
	
		serveInvalid(rw)

		return;
	}

	_, err = rw.Write([]byte("ACK\nNCK\n"))
	rw.Flush()

	if err != nil {
		log.Printf("rw.Write(): %v\n", err)
		return
	}

	nick, _, err := rw.ReadLine()

	if err != nil {
		log.Printf("rw.ReadLine(): %v\n", err)
		return
	}

	nickstr := string(nick)

	if nickstr == "__SERVER__" || nickstr == "__MOTD__" {
		log.Printf("%v tried to log in as reserved nick %s\n", conn.RemoteAddr(), nickstr)
		serveInvalid(rw)
		return
	}

	// Already logged on
	if isClientActive(nickstr) {
		serveInvalid(rw)
		return
	}

	if userExists(nickstr) {
		if !connLogin(rw, nickstr) {
			return
		}
	} else {
		if !connReg(rw, nickstr) {
			return
		}
	}

	addActiveClient(nickstr, rw)
	defer delActiveClient(nickstr)

	_, err = serveMotd(rw)
	if err != nil {
		log.Printf("serveMotd(): %v\n", err)
		return
	}

	for {
		request, _, err := rw.ReadLine()

		if err != nil {
			log.Printf("rw.ReadLine(): %v\n", err)
			return
		}

		reqType := string(request[0:3])

		switch reqType {
		case "STS": 
		_, err = serveStatus(rw, nickstr)
		if err != nil {
			log.Printf("serveStatus(%s): %v\n", nickstr, err)
			return
		}
		case "LST":
		_, err = serveList(rw)
		if err != nil {
			log.Printf("serveList(%s): %v\n", nickstr, err)
			return
		}
		case "ADM":
		err = serveMakeAdmin(rw, nickstr, string(request))	
		if err != nil {
			log.Printf("serveMakeAdmin(%s): %v\n", nickstr, err)
			if !errors.Is(err, ErrNoUser) && !errors.Is(err, ErrPerm) {
				return
			}
		}
		case "KCK":
		err = serveKick(rw, nickstr, string(request))
		if err != nil {
			log.Printf("serveKick(%s): %v\n", nickstr, err)
			if !errors.Is(err, ErrPerm) && !errors.Is(err, ErrNoUser) { 
				return
			}
		}
		case "BYE":
		serveAck(rw)
		return
		case "SHT":
		err = serveShutdown(rw, nickstr)
		if err != nil {
			log.Printf("serveShutdown(%s): %v\n", nickstr, err)
			return
		}
		case "NPW":
		err = serveNewPassword(rw, nickstr, string(request))
		if err != nil {
			log.Printf("serveNewPassword(%s): %v\n", nickstr, err)
			return
		}
		case "SPW":
		err = serveSetServerPassword(rw, nickstr, string(request))
		if err != nil {
			log.Printf("serveSetServerPassword(%s): %v\n", nickstr, err)
			if !errors.Is(err, ErrPerm) {
				return
			}
		}
		case "MSG":
		err = serveMsg(rw, nickstr, string(request))
		if err != nil {
			log.Printf("serveMsg(%s): %v\n", nickstr, err)
			return
		}
		default:
			serveInvalid(rw)
			return
		}
	}
}

func checkFatal(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v\n", what, err)
	}
}

func dbSetup() {
	_, err := db.Exec(`
		 CREATE TABLE IF NOT EXISTS users (
		 	nick STRING PRIMARY KEY,
		 	passhash BLOB,
			isAdmin BOOLEAN
	     );
	`)

	checkFatal(err, "db.Exec()")

	_, err = db.Exec(`
		 CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT
	     );
	`)

	checkFatal(err, "db.Exec()")

	_, err = db.Exec(`
		 INSERT OR IGNORE INTO config
		 (key, value) VALUES (?, ?)
	`, "serverPassword", "default_password")

	checkFatal(err, "db.Exec()")
}

func main() {
	port := flag.String("port", "8666", "Port that the server will listen at")
	dbPath := flag.String("db", "./users.db", "Filepath for user database")
	motdFilepathPtr := flag.String("motd", "", "MOTD to display to users upon login")
	certPtr := flag.String("cert", "./cert.pem", "Server TLS certificate")
	keyPtr := flag.String("key", "./key.pem", "Server TLS private key")
	flag.Parse()

	motdFilepath = *motdFilepathPtr

	if motdFilepath != "" {
		if _, err := os.Stat(motdFilepath);
		errors.Is(err, os.ErrNotExist) {
			log.Fatalf("MOTD file %s doesn't exist\n", motdFilepath)
		}
	}

	cert, err := tls.LoadX509KeyPair(*certPtr, *keyPtr)

	checkFatal(err, "tls.LoadX509KeyPair()")

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", ":" + *port, tlsConfig)

	checkFatal(err, "tls.Listen()")

	log.Printf("Listening on port %s\n", *port)

	db, err = sql.Open("sqlite3", *dbPath)
	defer db.Close()

	dbSetup()

	checkFatal(err, "sql.Open()")

	log.Println("Established connection to users.db")

	go broadcaster()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print("Accept(): %v\n", err)
			continue
		}
		go serveClient(conn)
	}
}
