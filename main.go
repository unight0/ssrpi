package main

import (
	"os"
	"errors"
	"fmt"
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

var db *sql.DB
var dbLock sync.Mutex

var clients []string
var clientsLock sync.Mutex

var motdFilepath string

func addActiveClient(nick string) {
	clientsLock.Lock()
	clients = append(clients, nick)
	clientsLock.Unlock()
}

func delActiveClient(nick string) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	var i int
	var e string
	for i, e = range clients {
		if e == nick {
			break
		}
	}
	// No such client
	if e != nick {
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

	if err != nil {
		log.Fatalf("db.QueryRow(): %v\n", err)
	}

	return exists
}

func userPassword(nick string) [sha256.Size]byte {
	var passhash []byte

	dbLock.Lock()
	err := db.QueryRow("SELECT passhash FROM users WHERE nick = ?", nick).Scan(&passhash)
	dbLock.Unlock()

	if err != nil {
		log.Fatalf("db.QueryRow(): %v\n", err)
	}

	return [32]byte(passhash)
}

func isUserAdmin(nick string) bool {
	var isAdmin bool 

	dbLock.Lock()
	err := db.QueryRow("SELECT isAdmin FROM users WHERE nick = ?", nick).Scan(&isAdmin)
	dbLock.Unlock()

	if err != nil {
		log.Fatalf("db.QueryRow(): %v\n", err)
	}

	return isAdmin
}

func countUsers() uint {
	var count uint

	dbLock.Lock()
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	dbLock.Unlock()

	if err != nil {
		log.Fatalf("db.QueryRow(): %v\n", err)
	}

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

	if err != nil {
		log.Fatalf("db.Exec(): %v\n", err)
	}
}

func connLogin(rw *bufio.ReadWriter, nick string) bool {
	_, err := rw.Write([]byte("PWD\n"))
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
		rw.Write([]byte("INV\n"))
		rw.Flush()

		log.Printf("Invalid password for %v\n", nick)
		return false
	}

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

	log.Printf("Registered %v\n", nick)

	return true
}

func sendMessage(rw *bufio.ReadWriter, msg string) (n int, err error) {
	return fmt.Fprintf(rw, "MSG __SERVER__ %d\n%s", len(msg), msg)
}

func serveStatus(rw *bufio.ReadWriter, nick string) (n int, err error) {
	isAdmin := isUserAdmin(nick)

	n, err = sendMessage(rw,
		fmt.Sprintf("STATUS\nYOUR NICK: %s\nARE YOU AN ADMIN: %t\n",
					 nick,
					 isAdmin))
	rw.Flush()
	return
}

func serveList(rw *bufio.ReadWriter) (n int, err error) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	var message string

	for _, e := range clients {
		message += fmt.Sprintf("%s\n", e)
	}

	n, err = sendMessage(rw, message)
	rw.Flush()
	return
}

func serveInvalid(rw *bufio.ReadWriter) {
	rw.Write([]byte("INV\n"))
	rw.Flush()
}

func serveMotd(rw *bufio.ReadWriter) (n int, err error) {
	if motdFilepath == "" {
		return 0, nil
	}

	motd, err := os.ReadFile(motdFilepath)

	n, err = sendMessage(rw, string(motd))
	rw.Flush()
	return
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

	correctHash := sha256.Sum256([]byte("secure_password"))

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

	if userExists(nickstr) {
		if !connLogin(rw, nickstr) {
			return
		}
	} else {
		if !connReg(rw, nickstr) {
			return
		}
	}

	addActiveClient(nickstr)
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
			log.Printf("serveStatus(): %v\n", err)
			return
		}
		case "LST":
		_, err = serveList(rw)
		if err != nil {
			log.Printf("serveList(): %v\n", err)
			return
		}
		default:
			serveInvalid(rw)
			return
		}
	}
}

func main() {
	port := flag.String("port", "8666", "Port that the server will listen at")
	dbPath := flag.String("db", "./users.db", "Filepath for user database")
	motdFilepathPtr := flag.String("motd", "", "MOTD to display to users upon login")
	flag.Parse()

	motdFilepath = *motdFilepathPtr

	if motdFilepath != "" {
		if _, err := os.Stat(motdFilepath);
		errors.Is(err, os.ErrNotExist) {
			log.Fatalf("MOTD file %s doesn't exist\n", motdFilepath)
		}
	}

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")

	if err != nil {
		log.Fatalln(err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", ":" + *port, tlsConfig)

	if err != nil {
		log.Fatalln(err)
		return
	}

	db, err = sql.Open("sqlite3", *dbPath)
	defer db.Close()
	log.Println("Established connection to users.db")

	_, err = db.Exec(
		`CREATE TABLE IF NOT EXISTS users (
		 	nick STRING PRIMARY KEY,
		 	passhash BLOB,
			isAdmin BOOLEAN
	     );
	`)

	if err != nil {
		log.Printf("db.Exec(): %v\n", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print("Accept(): %v\n", err)
			continue
		}
		go serveClient(conn)
	}
}
