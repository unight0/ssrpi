/* ======================================================================
 * Copyleft (C) 2026
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * ======================================================================
*/


package main

import (
	"os"
	"errors"
	"fmt"
	"io"
	"flag"
	"bufio"
	"net"
	"log"
	"sync"
	"crypto/tls"
	"crypto/sha256"
	"crypto/rand"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var errNoResource = errors.New("No such resource")
var errPerm = errors.New("Action not allowed")
var errNoUser = errors.New("User doesn't exist")

var db *sql.DB
var dbLock sync.Mutex

// Active Client
type AClient struct {
	nick string
	rw *bufio.ReadWriter
}

var clients map[string]AClient
var clientsLock sync.Mutex

// Binary resource
type BResource struct {
	origin string
	size uint
	offloadFile *os.File
}

var resources map[string]BResource
var resourcesLock sync.RWMutex

var motdFilepath string

func isClientActive(nick string) bool {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	_, exists := clients[nick]

	return exists
}

func addActiveClient(nick string, rw *bufio.ReadWriter) {
	clientsLock.Lock()
	clients[nick] = AClient{nick, rw}
	clientsLock.Unlock()
}

func delActiveClient(nick string) {
	clientsLock.Lock()
	delete(clients, nick)
	clientsLock.Unlock()
}

func userExists(nick string) bool {
	var exists bool

	dbLock.Lock()
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE nick = ?)", nick).Scan(&exists)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return exists
}

func userPassword(nick string) ([]byte, [sha256.Size]byte) {
	var salt, passhash []byte

	dbLock.Lock()
	err := db.QueryRow("SELECT salt, passhash FROM users WHERE nick = ?", nick).Scan(&salt, &passhash)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return salt, [sha256.Size]byte(passhash)
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

func registerUser(nick string, salt []byte, passhash [sha256.Size]byte) {
	isAdmin := countUsers() == 0

	dbLock.Lock()
	_, err := db.Exec(
		"INSERT INTO users (nick, salt, passhash, isAdmin) VALUES (?, ?, ?, ?)",
		nick,
		salt,
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

func getServerPassword() ([]byte, [sha256.Size]byte) {
	var salt, hash []byte

	dbLock.Lock()
	err := db.QueryRow("SELECT value, value2 FROM config WHERE key = ?", "serverPassword").Scan(&salt, &hash)
	dbLock.Unlock()

	checkFatal(err, "db.QueryRow()")

	return salt, [sha256.Size]byte(hash)
}

func setServerPassword(salt []byte, hash [sha256.Size]byte) {
	dbLock.Lock()
	_, err := db.Exec("UPDATE config SET value = ?, value2 =  ? WHERE key = ?", 
		salt, hash[:], "serverPassword")
	dbLock.Unlock()

	checkFatal(err, "db.Exec()")
}

func setUserPassword(nick string, salt []byte, passhash [sha256.Size]byte) {
	dbLock.Lock()
	_, err := db.Exec("UPDATE users SET salt = ?,  passhash = ? WHERE nick = ?", salt, passhash[:], nick)
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

	salt, correctHash := userPassword(nick)
	passwdHash := saltedHash(salt, passwd)

	if passwdHash != correctHash {
		serveInvalid(rw)

		log.Printf("Invalid password for %v\n", nick)
		return false
	}

	serveAck(rw)

	log.Printf("%v logged in\n", nick)

	return true
}

func makeSalt() []byte {
	salt := make([]byte, 32)
	rand.Read(salt)

	return salt
}

func saltedHash(salt, what []byte) [sha256.Size]byte {
	what = append(salt, what...)

	return sha256.Sum256(what)
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


	salt := makeSalt()
	passwdHash := saltedHash(salt, passwd)

	registerUser(nick, salt, passwdHash)

	serveAck(rw)

	log.Printf("Registered %v\n", nick)

	return true
}

func sendMessage(rw *bufio.ReadWriter, origin string, msg []byte) (int, error) {
	return fmt.Fprintf(rw, "MSG %s %d\n%s", origin, len(msg), msg)
}

func sendSay(rw *bufio.ReadWriter, origin string, msg []byte) (int, error) {
	return fmt.Fprintf(rw, "SAY %s %d\n%s", origin, len(msg), msg)
}

func serveUpload(rw *bufio.ReadWriter, nick, header string) error {
	var size uint
	var id string

	_, err := fmt.Sscanf(header, "UPL %s %d", &id, &size)
	if err != nil {
		serveInvalid(rw)
		return err
	}

	file, err := os.CreateTemp("", "ssrpi-serv-resource-*")
	if err != nil {
		return err
	}

	os.Remove(file.Name())

	_, err = io.CopyN(file, rw, int64(size))
	if err != nil {
		return err
	}

	serveAck(rw)

	resourcesLock.Lock()
	resources[id] = BResource{nick, size, file}
	resourcesLock.Unlock()

	// Notify everyone about the resource
	clientsLock.Lock()
	for n, c := range clients {
		if n == nick {
			continue
		}
	
		_, err := c.rw.WriteString(fmt.Sprintf(
				"UPL %s %s %d\n", 
				nick, id, size,
			))
		c.rw.Flush()
	
		if err != nil {
			logError("c.rw.WriteString()", nick, err)
		}
	}
	clientsLock.Unlock()


	return nil
}

func serveGet(rw *bufio.ReadWriter, nick, header string) error {
	var id string

	_, err := fmt.Sscanf(header, "GET %s", &id)
	if err != nil {
		serveInvalid(rw)
		return err
	}

	resourcesLock.RLock()
	defer resourcesLock.RUnlock()

	res, ok := resources[id]

	if !ok {
		serveInvalid(rw)
		return errNoResource
	}
	
	rw.WriteString(fmt.Sprintf("GET %s %d\n", id, res.size))
	rw.Flush()

	_, err = io.Copy(rw, io.NewSectionReader(res.offloadFile, 0, int64(res.size)))

	if err != nil {
		return err
	}

	rw.Flush()
	
	return nil
}

func serveStatus(rw *bufio.ReadWriter, nick string) (err error) {
	isAdmin := isUserAdmin(nick)

	_, err = sendMessage(rw, "__SERVER__",
		[]byte(fmt.Sprintf("STATUS\nNICK: %s\nADMIN: %t\n",
					 nick,
					 isAdmin)))
	rw.Flush()
	return
}

func serveList(rw *bufio.ReadWriter) (err error) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	var message string

	for nick, _ := range clients {
		message += fmt.Sprintf("%s\n", nick)
	}

	_, err = sendMessage(rw, "__SERVER__", []byte(message))
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

func serveMotd(rw *bufio.ReadWriter) (err error) {
	if motdFilepath == "" {
		return nil
	}

	motd, err := os.ReadFile(motdFilepath)

	_, err = sendMessage(rw, "__MOTD__", motd)
	rw.Flush()
	return
}

func serveMsg(rw *bufio.ReadWriter, nick, header string) error {
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

	log.Printf("Broadcasting '%s'\n", msg)
	
	clientsLock.Lock()
	for n, c := range clients {
		if n == nick {
			continue
		}
	
		_, err := sendMessage(c.rw, nick, msg)
		c.rw.Flush()
	
		if err != nil {
			log.Printf("sendMessage(): %v\n", err)
		}
	}
	clientsLock.Unlock()

	serveAck(rw)

	return nil
}

func serveSay(rw *bufio.ReadWriter, nick, header string) error {
	var msgLen uint
	var whom string

	_, err := fmt.Sscanf(header, "SAY %s %d", &whom, &msgLen)

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

	clientsLock.Lock()
	defer clientsLock.Unlock()

	c, ok := clients[whom]

	if !ok {
		serveInvalid(rw)
		return errNoUser
	}

	_, err = sendSay(c.rw, nick, msg)
	c.rw.Flush()

	serveAck(rw)

	return err
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
		return errNoUser
	}

	can := isUserAdmin(nick)

	if !can {
		serveInvalid(rw)
		return errPerm
	}

	makeUserAdmin(whom, val)
	serveAck(rw)

	return nil
}

func kick(nick string) error {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	c, ok := clients[nick]

	if !ok {
		return errNoUser
	}

	c.rw.WriteString("KCK\n")
	c.rw.Flush()

	delete(clients, nick)

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
		return errPerm
	}

	if !userExists(whom) {
		serveInvalid(rw)
		return errNoUser
	}

	err = kick(whom)
	serveAck(rw)

	return nil
}

func serveShutdown(rw *bufio.ReadWriter, nick string) (err error) {
	if !isUserAdmin(nick) {
		serveInvalid(rw)
		return errPerm
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
		return errPerm
	}

	salt := makeSalt()
	hash := saltedHash(salt, []byte(newpass))

	setServerPassword(salt, hash)
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

	salt := make([]byte, 32)

	rand.Read(salt)

	newpassBytes := []byte(newpass)
	newpassBytes = append(salt, newpassBytes...)

	passhash := sha256.Sum256(newpassBytes)

	setUserPassword(nick, salt, passhash)
	serveAck(rw)

	return nil
}

func logError(what, who string, err error) {
	log.Printf("(%s) %s: %v\n", who, what, err)
}

func serveClient(conn net.Conn) {
	defer conn.Close()

	rw := bufio.NewReadWriter(
		bufio.NewReader(conn),
		bufio.NewWriter(conn),
	)

	_, err := rw.WriteString("PWD\n")
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

	salt, correctHash := getServerPassword()

	passwdHash := saltedHash(salt, passwd)

	if passwdHash != correctHash {
		log.Printf("Invalid password provided by %v\n", conn.RemoteAddr())
	
		serveInvalid(rw)

		return;
	}

	_, err = rw.WriteString("ACK\nNCK\n")
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

	err = serveMotd(rw)
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

		reqStr := string(request)
		reqType := string(request[0:3])

		switch reqType {
		case "UPL":
		err = serveUpload(rw, nickstr, reqStr)
		if err != nil {
			logError("serveUpload()", nickstr, err)
			return
		}
		case "GET":
		err = serveGet(rw, nickstr, reqStr)
		if err != nil {
			logError("serveGet()", nickstr, err)
			if !errors.Is(err, errNoResource) {
				return
			}
		}
		case "STS": 
		err = serveStatus(rw, nickstr)
		if err != nil {
			logError("serveStatus()", nickstr, err)
			return
		}
		case "LST":
		err = serveList(rw)
		if err != nil {
			logError("serveList()", nickstr, err)
			return
		}
		case "ADM":
		err = serveMakeAdmin(rw, nickstr, reqStr)	
		if err != nil {
			logError("serveMakeAdmin()", nickstr, err)
			if !errors.Is(err, errNoUser) && !errors.Is(err, errPerm) {
				return
			}
		}
		case "KCK":
		err = serveKick(rw, nickstr, reqStr)
		if err != nil {
			logError("serveKick()", nickstr, err)
			if !errors.Is(err, errPerm) && !errors.Is(err, errNoUser) { 
				return
			}
		}
		case "BYE":
		serveAck(rw)
		return
		case "SHT":
		err = serveShutdown(rw, nickstr)
		if err != nil {
			logError("serveShutdown()", nickstr, err)
			return
		}
		case "NPW":
		err = serveNewPassword(rw, nickstr, reqStr)
		if err != nil {
			logError("serveNewPassword()", nickstr, err)
			return
		}
		case "SPW":
		err = serveSetServerPassword(rw, nickstr, reqStr)
		if err != nil {
			logError("serveSetServerPassword()", nickstr, err)
			if !errors.Is(err, errPerm) {
				return
			}
		}
		case "MSG":
		err = serveMsg(rw, nickstr, reqStr)
		if err != nil {
			logError("serveMsg()", nickstr, err)
			return
		}
		case "SAY":
		err = serveSay(rw, nickstr, reqStr)
		if err != nil {
			logError("serveSay()", nickstr, err)
			if !errors.Is(err, errNoUser) {
				return
			}
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
			salt BLOB,
		 	passhash BLOB,
			isAdmin BOOLEAN
	     );
	`)

	checkFatal(err, "db.Exec()")

	_, err = db.Exec(`
		 CREATE TABLE IF NOT EXISTS config (
			key BLOB PRIMARY KEY,
			value BLOB,
			value2 BLOB
	     );
	`)

	checkFatal(err, "db.Exec()")

	salt := makeSalt()
	hash := saltedHash(salt, []byte("default_password"))

	_, err = db.Exec(`
		 INSERT OR IGNORE INTO config
		 (key, value, value2) VALUES (?, ?, ?)
		 `, "serverPassword", salt, hash[:])

	checkFatal(err, "db.Exec()")
}

func GNUHello() {
    fmt.Printf("ssrpi-serv Copyleft (C) 2026\n" +
    	"This program comes with ABSOLUTELY NO WARRANTY\n" +
    	"This is free software, and you are welcome to redistribute it\n" +
    	"under certain conditions; see LICENSE for details\n" + 
    	"=============================================================\n",
	)
}

func main() {
	GNUHello()	


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

	clients = make(map[string]AClient)
	resources = make(map[string]BResource)

	dbSetup()

	checkFatal(err, "sql.Open()")

	log.Println("Established connection to users.db")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept(): %v\n", err)
			continue
		}
		go serveClient(conn)
	}
}
