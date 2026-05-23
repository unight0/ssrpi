package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"golang.org/x/term"
)

var nickname string
var servpass string
var password string

type terminal struct {
	mu     sync.Mutex
	buf    []byte
	prompt string
}

func newTerminal(prompt string) *terminal {
	return &terminal{prompt: prompt}
}

func (t *terminal) printMessage(msg string) {
	t.mu.Lock()
	fmt.Printf("\r\033[K%s\r\n%s%s", msg, t.prompt, string(t.buf))
	t.mu.Unlock()
}

func (t *terminal) redrawInput() {
	fmt.Printf("\r\033[K%s%s", t.prompt, string(t.buf))
}

func handshake(rw *bufio.ReadWriter, t *terminal) bool {
	line, _, err := rw.ReadLine()

	if err != nil {
		t.printMessage(fmt.Sprintf("[ERROR] %v", err))
		return false
	}

	if string(line) != "PWD" {
		t.printMessage(fmt.Sprintf("[ERROR] Invalid server handshake: %s", line))
		return false
	}

	rw.WriteString(servpass + "\n")
	rw.Flush()

	line, _, err = rw.ReadLine()

	if err != nil {
		t.printMessage(fmt.Sprintf("[ERROR] %v", err))
		return false
	}

	if string(line) != "NCK" {
		t.printMessage(fmt.Sprintf("[ERROR] Invalid server handshake: %s", line))
		return false
	}

	rw.WriteString(nickname + "\n")
	rw.Flush()

	line, _, err = rw.ReadLine()

	if err != nil {
		t.printMessage(fmt.Sprintf("[ERROR] %v", err))
		return false
	}

	if string(line) != "PWD" && string(line) != "NPW" {
		t.printMessage(fmt.Sprintf("[ERROR] Invalid server handshake: %s", line))
		return false
	}

	rw.WriteString(password + "\n")
	rw.Flush()

	return true
}

func worker(server string, t *terminal) {
	conn, err := tls.Dial("tcp", server, &tls.Config{InsecureSkipVerify: true})
	defer conn.Close()

	if err != nil {
		log.Fatalln(err)
	}

	if len(conn.ConnectionState().PeerCertificates) == 0 || !conn.ConnectionState().HandshakeComplete {
		t.printMessage("[WARNING] could not verify server identity")
	} else if conn.ConnectionState().PeerCertificates[0].IsCA {
		t.printMessage("[WARNING] server certificate is self-signed")
	}
	
	rw := bufio.NewReadWriter(
		bufio.NewReader(conn),
		bufio.NewWriter(conn),
	)

	if !handshake(rw, t) {
		return
	}

	for {
		var buf []byte
		_, err := rw.Read(buf)

		if err != nil {
			t.printMessage(fmt.Sprintf("[ERROR] %v", err))
			return
		}

		t.printMessage(string(buf))
	}
}

func main() {
	serverPtr := flag.String("server", "localhost:8666", "Specify the server and port to connect to")
	servpassPtr := flag.String("servpass", "", "Specify server password")
	nicknamePtr := flag.String("nick", "", "Specify your nickname")
	passwordPtr := flag.String("pass", "", "Specify your password")
	flag.Parse()

	server := *serverPtr
	nickname = *nicknamePtr
	password = *passwordPtr
	servpass = *servpassPtr

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	t := newTerminal(": ")
	fmt.Print(t.prompt)

	go worker(server, t)

	one := make([]byte, 1)
	for {
		_, err := os.Stdin.Read(one)
		if err != nil {
			break
		}
		ch := one[0]

		t.mu.Lock()
		switch {
		case ch == 127 || ch == 8: // backspace
			if len(t.buf) > 0 {
				t.buf = t.buf[:len(t.buf)-1]
			}
		case ch == '\r' || ch == '\n': // enter
			text := string(t.buf)
			t.buf = t.buf[:0]
			fmt.Printf("\r\033[K[me]: %s\r\n%s", text, t.prompt)
			t.mu.Unlock()
			continue
		case ch == 3: // ctrl-c
			t.mu.Unlock()
			fmt.Println()
			return
		case ch >= 32 && ch <= 126: // printable
			t.buf = append(t.buf, ch)
		}
		t.redrawInput()
		t.mu.Unlock()
	}
}
