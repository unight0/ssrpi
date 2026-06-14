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
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// States

type state int

const (
	stateLogin      state = iota // Interactive login form
	stateConnecting              // Handshaking with server
	statePassword                // User password prompt (after server tells us login/register)
	stateChat                    // Main chat
	stateError                   // Fatal error, press any key to exit
)

type loginStep int

const (
	stepServer   loginStep = iota
	stepServPass
	stepNick
	stepCount
)

// Tea messages

type needPassMsg struct {
	isNew bool
	conn  net.Conn
	rw    *bufio.ReadWriter
}

type connectedMsg struct{}

type serverMsg struct {
	origin  string
	content string
}

type sayMsg struct {
	origin  string
	content string
}

type uplNotifyMsg struct {
	origin string
	alias  string
	id     string
	size   uint
}

type getResponseMsg struct {
	id   string
	data []byte
}

type ackMsg struct{}
type invMsg struct{ reason string }
type serverErrMsg struct{}
type kickedMsg struct{}
type byeMsg struct{}
type errMsg struct{ err error }

// Styles

var (
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("170"))
	infoStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	labelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	valueStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("135"))
	nickStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("135"))
	serverStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	motdStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	dmStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	errStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	separatorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	promptStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("170"))
)

// Login step definitions

var stepInfo = [stepCount]struct {
	label       string
	placeholder string
	masked      bool
}{
	stepServer:   {"Server address", "localhost:8666", false},
	stepServPass: {"Server password", "", true},
	stepNick:     {"Nickname", "", false},
}

// Login entry (completed field for display)

type loginEntry struct {
	label  string
	value  string
	masked bool
}

func (e loginEntry) render() string {
	v := e.value
	if e.masked && v != "" {
		v = strings.Repeat("•", len(v))
	}
	return "  " + labelStyle.Render(e.label+": ") + valueStyle.Render(v)
}

// Model

type model struct {
	state state

	server   string
	servpass string
	nick     string
	userpass string

	conn net.Conn
	rw   *bufio.ReadWriter

	// Login UI
	loginStep    loginStep
	loginInput   textinput.Model
	loginEntries []loginEntry
	isNewUser    bool
	loginErr     string

	// Chat UI
	viewport        viewport.Model
	chatInput       textinput.Model
	messages        []string
	connected       bool
	ready           bool
	resourceAliases map[string]string

	width    int
	height   int
	quitting bool
}

func newModel(server, servpass, nick, userpass string) model {
	ti := textinput.New()
	ti.Focus()
	ti.Prompt = "  > "
	ti.PromptStyle = promptStyle
	ti.CharLimit = 256

	m := model{
		state:      stateLogin,
		server:     server,
		servpass:   servpass,
		nick:       nick,
		userpass:   userpass,
		loginInput: ti,
	}

	m.loginStep = m.nextStep(-1)
	if m.loginStep >= stepCount {
		m.state = stateConnecting
	} else {
		m.configureLoginInput()
	}

	return m
}

func (m *model) nextStep(from loginStep) loginStep {
	for s := from + 1; s < stepCount; s++ {
		switch s {
		case stepServer:
			if m.server != "" {
				continue
			}
		case stepServPass:
			if m.servpass != "" {
				continue
			}
		case stepNick:
			if m.nick != "" {
				continue
			}
		}
		return s
	}
	return stepCount
}

func (m *model) configureLoginInput() {
	info := stepInfo[m.loginStep]
	m.loginInput.Placeholder = info.placeholder
	m.loginInput.Reset()
	if info.masked {
		m.loginInput.EchoMode = textinput.EchoPassword
		m.loginInput.EchoCharacter = '•'
	} else {
		m.loginInput.EchoMode = textinput.EchoNormal
	}
}

func (m model) Init() tea.Cmd {
	if m.state == stateConnecting {
		return connectPhase1(m.server, m.servpass, m.nick)
	}
	return textinput.Blink
}

// Commands

func connectPhase1(server, servpass, nick string) tea.Cmd {
	return func() tea.Msg {
		conn, err := tls.Dial("tcp", server, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return errMsg{err}
		}

		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

		if line, err := readLine(rw); err != nil {
			conn.Close()
			return errMsg{err}
		} else if line != "PWD" {
			conn.Close()
			return errMsg{fmt.Errorf("expected PWD, got %s", line)}
		}
		writeLine(rw, servpass)

		if line, err := readLine(rw); err != nil {
			conn.Close()
			return errMsg{err}
		} else if strings.HasPrefix(line, "INV") {
			conn.Close()
			return errMsg{fmt.Errorf("invalid server password")}
		} else if line != "ACK" {
			conn.Close()
			return errMsg{fmt.Errorf("expected ACK, got %s", line)}
		}

		if line, err := readLine(rw); err != nil {
			conn.Close()
			return errMsg{err}
		} else if line != "NCK" {
			conn.Close()
			return errMsg{fmt.Errorf("expected NCK, got %s", line)}
		}
		writeLine(rw, nick)

		line, err := readLine(rw)
		if err != nil {
			conn.Close()
			return errMsg{err}
		}
		switch {
		case line == "PWD":
			return needPassMsg{false, conn, rw}
		case line == "NPW":
			return needPassMsg{true, conn, rw}
		case strings.HasPrefix(line, "INV"):
			reason := strings.TrimSpace(strings.TrimPrefix(line, "INV"))
			conn.Close()
			if reason != "" {
				return errMsg{fmt.Errorf("nickname rejected: %s", reason)}
			}
			return errMsg{fmt.Errorf("nickname rejected")}
		default:
			conn.Close()
			return errMsg{fmt.Errorf("expected PWD/NPW, got %s", line)}
		}
	}
}

func finishAuth(rw *bufio.ReadWriter, userpass string) tea.Cmd {
	return func() tea.Msg {
		writeLine(rw, userpass)

		line, err := readLine(rw)
		if err != nil {
			return errMsg{err}
		}
		if strings.HasPrefix(line, "INV") {
			return errMsg{fmt.Errorf("invalid password")}
		}
		if line != "ACK" {
			return errMsg{fmt.Errorf("expected ACK, got %s", line)}
		}

		return connectedMsg{}
	}
}

func listenServer(rw *bufio.ReadWriter) tea.Cmd {
	return func() tea.Msg {
		line, err := readLine(rw)
		if err != nil {
			return errMsg{err}
		}

		switch {
		case line == "ACK":
			return ackMsg{}
		case line == "ERR":
			return serverErrMsg{}
		case strings.HasPrefix(line, "INV"):
			reason := strings.TrimPrefix(line, "INV")
			reason = strings.TrimSpace(reason)
			return invMsg{reason}
		case line == "KCK":
			return kickedMsg{}
		case line == "BYE":
			return byeMsg{}
		case strings.HasPrefix(line, "MSG "):
			var origin string
			var length int
			if _, err := fmt.Sscanf(line, "MSG %s %d", &origin, &length); err != nil {
				return errMsg{fmt.Errorf("bad MSG header: %s", line)}
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(rw, body); err != nil {
				return errMsg{err}
			}
			return serverMsg{origin, string(body)}
		case strings.HasPrefix(line, "SAY "):
			var origin string
			var length int
			if _, err := fmt.Sscanf(line, "SAY %s %d", &origin, &length); err != nil {
				return errMsg{fmt.Errorf("bad SAY header: %s", line)}
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(rw, body); err != nil {
				return errMsg{err}
			}
			return sayMsg{origin, string(body)}
		case strings.HasPrefix(line, "UPL "):
			var origin string
			var alias string
			var id string
			var size uint
			if _, err := fmt.Sscanf(line, "UPL %s %s %s %d", &origin, &alias, &id, &size); err != nil {
				return errMsg{fmt.Errorf("bad UPL header: %s", line)}
			}
			return uplNotifyMsg{origin, alias, id, size}
		case strings.HasPrefix(line, "GET "):
			var id string
			var length int
			if _, err := fmt.Sscanf(line, "GET %s %d", &id, &length); err != nil {
				return errMsg{fmt.Errorf("bad GET header: %s", line)}
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(rw, body); err != nil {
				return errMsg{err}
			}
			return getResponseMsg{id, body}
		default:
			return errMsg{fmt.Errorf("unknown server message: %s", line)}
		}
	}
}

// Update

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			if m.conn != nil {
				if m.connected {
					m.rw.WriteString("BYE\n")
					m.rw.Flush()
				}
				m.conn.Close()
			}
			return m, tea.Quit
		}
		switch m.state {
		case stateError:
			m.quitting = true
			return m, tea.Quit
		case stateLogin:
			return m.updateLogin(msg)
		case statePassword:
			return m.updatePassword(msg)
		case stateChat:
			return m.updateChat(msg)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.loginInput.Width = max(m.width-6, 1)
		if m.state == stateChat {
			m.resizeChat()
		}
		return m, nil

	case needPassMsg:
		m.conn = msg.conn
		m.rw = msg.rw
		m.isNewUser = msg.isNew
		if m.userpass != "" {
			m.state = stateChat
			m.initChat()
			return m, tea.Batch(textinput.Blink, finishAuth(m.rw, m.userpass))
		}
		m.state = statePassword
		m.loginInput.Reset()
		m.loginInput.EchoMode = textinput.EchoPassword
		m.loginInput.EchoCharacter = '•'
		m.loginInput.Placeholder = ""
		return m, textinput.Blink

	case connectedMsg:
		m.connected = true
		if m.state != stateChat {
			m.state = stateChat
			m.initChat()
		}
		return m, listenServer(m.rw)

	case serverMsg:
		m.appendMsg(msg.origin, msg.content)
		return m, listenServer(m.rw)

	case sayMsg:
		m.appendDm(msg.origin, msg.content)
		return m, listenServer(m.rw)

	case uplNotifyMsg:
		if m.resourceAliases == nil {
			m.resourceAliases = make(map[string]string)
		}
		m.resourceAliases[msg.alias] = msg.id
		m.appendSys(fmt.Sprintf("%s uploaded '%s' [%s] (%d bytes) — /get %s to download", msg.origin, msg.alias, msg.id, msg.size, msg.alias))
		return m, listenServer(m.rw)

	case getResponseMsg:
		name := sanitizeFilename(msg.id)
		dir := "downloads"
		os.MkdirAll(dir, 0755)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, msg.data, 0644); err != nil {
			m.appendSys(errStyle.Render("Failed to save " + path + ": " + err.Error()))
		} else {
			m.appendSys(fmt.Sprintf("Saved '%s' (%d bytes)", path, len(msg.data)))
		}
		return m, listenServer(m.rw)

	case ackMsg:
		//m.appendSys("OK")
		return m, listenServer(m.rw)

	case invMsg:
		if msg.reason != "" {
			m.appendSys("Rejected: " + msg.reason)
		} else {
			m.appendSys("Request rejected by server")
		}
		return m, listenServer(m.rw)

	case serverErrMsg:
		m.appendSys(errStyle.Render("Server error"))
		return m, listenServer(m.rw)

	case kickedMsg:
		m.connected = false
		if m.conn != nil {
			m.conn.Close()
		}
		m.loginErr = "You have been kicked"
		m.state = stateError
		return m, nil

	case byeMsg:
		m.connected = false
		if m.conn != nil {
			m.conn.Close()
		}
		m.loginErr = "Server shut down"
		m.state = stateError
		return m, nil

	case errMsg:
		if m.state == stateError {
			return m, nil
		}
		m.connected = false
		if m.conn != nil {
			m.conn.Close()
		}
		m.loginErr = "Disconnected: " + msg.err.Error()
		m.state = stateError
		return m, nil
	}

	// Pass through to sub-components
	var cmd tea.Cmd
	switch m.state {
	case stateLogin, statePassword:
		m.loginInput, cmd = m.loginInput.Update(msg)
	case stateError:
		return m, nil
	case stateChat:
		var cmd2 tea.Cmd
		m.chatInput, cmd = m.chatInput.Update(msg)
		m.viewport, cmd2 = m.viewport.Update(msg)
		return m, tea.Batch(cmd, cmd2)
	}
	return m, cmd
}

func (m model) updateLogin(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type != tea.KeyEnter {
		var cmd tea.Cmd
		m.loginInput, cmd = m.loginInput.Update(msg)
		return m, cmd
	}

	val := strings.TrimSpace(m.loginInput.Value())
	info := stepInfo[m.loginStep]

	// Use placeholder as default
	if val == "" && info.placeholder != "" {
		val = info.placeholder
	}
	if val == "" {
		return m, nil
	}

	switch m.loginStep {
	case stepServer:
		m.server = val
	case stepServPass:
		m.servpass = val
	case stepNick:
		m.nick = val
	}

	m.loginEntries = append(m.loginEntries, loginEntry{info.label, val, info.masked})
	m.loginStep = m.nextStep(m.loginStep)

	if m.loginStep >= stepCount {
		m.state = stateConnecting
		return m, connectPhase1(m.server, m.servpass, m.nick)
	}

	m.configureLoginInput()
	return m, nil
}

func (m model) updatePassword(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type != tea.KeyEnter {
		var cmd tea.Cmd
		m.loginInput, cmd = m.loginInput.Update(msg)
		return m, cmd
	}

	val := m.loginInput.Value()
	if val == "" {
		return m, nil
	}

	m.userpass = val
	m.state = stateChat
	m.initChat()
	return m, tea.Batch(textinput.Blink, finishAuth(m.rw, m.userpass))
}

func (m model) updateChat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyEnter {
		text := strings.TrimSpace(m.chatInput.Value())
		if text == "" || !m.connected {
			return m, nil
		}
		m.chatInput.Reset()
		return m, m.handleInput(text)
	}

	var cmd, cmd2 tea.Cmd
	m.chatInput, cmd = m.chatInput.Update(msg)
	m.viewport, cmd2 = m.viewport.Update(msg)
	return m, tea.Batch(cmd, cmd2)
}

// Chat setup

func (m *model) initChat() {
	ti := textinput.New()
	ti.Placeholder = "Type a message... (/help for commands)"
	ti.Focus()
	ti.Prompt = "> "
	ti.PromptStyle = promptStyle
	ti.CharLimit = 4096
	if m.width > 0 {
		ti.Width = max(m.width-3, 1)
	}
	m.chatInput = ti

	if m.width > 0 && m.height > 0 {
		m.resizeChat()
	}
}

func (m *model) resizeChat() {
	vpHeight := max(m.height-3, 1)
	if !m.ready {
		m.viewport = viewport.New(m.width, vpHeight)
		m.ready = true
	} else {
		m.viewport.Width = m.width
		m.viewport.Height = vpHeight
	}
	m.chatInput.Width = max(m.width-3, 1)
	m.viewport.SetContent(strings.Join(m.messages, "\n"))
}

// Input handling

func (m *model) handleInput(text string) tea.Cmd {
	if strings.HasPrefix(text, "/") {
		return m.handleCommand(text)
	}

	msg := []byte(text)
	fmt.Fprintf(m.rw, "MSG %d\n%s", len(msg), msg)
	m.rw.Flush()

	m.appendMsg(m.nick, text)
	return nil
}

func (m *model) handleCommand(text string) tea.Cmd {
	parts := strings.Fields(text)
	switch strings.ToLower(parts[0]) {
	case "/quit", "/q":
		m.quitting = true
		if m.conn != nil {
			if m.connected {
				m.rw.WriteString("BYE\n")
				m.rw.Flush()
			}
			m.conn.Close()
		}
		return tea.Quit
	case "/status", "/s":
		m.rw.WriteString("STS\n")
		m.rw.Flush()
	case "/list", "/l":
		m.rw.WriteString("LST\n")
		m.rw.Flush()
	case "/kick", "/k":
		if len(parts) != 2 {
			m.appendSys("Usage: /kick <nick>")
			return nil
		}
		fmt.Fprintf(m.rw, "KCK %s\n", parts[1])
		m.rw.Flush()
	case "/admin":
		if len(parts) != 3 {
			m.appendSys("Usage: /admin <nick> <0|1>")
			return nil
		}
		fmt.Fprintf(m.rw, "ADM %s %s\n", parts[1], parts[2])
		m.rw.Flush()
	case "/password", "/pw":
		if len(parts) != 2 {
			m.appendSys("Usage: /password <newpassword>")
			return nil
		}
		fmt.Fprintf(m.rw, "NPW %s\n", parts[1])
		m.rw.Flush()
	case "/setpass":
		if len(parts) != 2 {
			m.appendSys("Usage: /setpass <password>")
			return nil
		}
		fmt.Fprintf(m.rw, "SPW %s\n", parts[1])
		m.rw.Flush()
	case "/say", "/dm":
		if len(parts) < 3 {
			m.appendSys("Usage: /say <nick> <message>")
			return nil
		}
		body := strings.Join(parts[2:], " ")
		msg := []byte(body)
		fmt.Fprintf(m.rw, "SAY %s %d\n%s", parts[1], len(msg), msg)
		m.rw.Flush()
		m.appendDm("to "+parts[1], body)
	case "/upload", "/upl":
		if len(parts) < 2 {
			m.appendSys("Usage: /upload <filepath> [nick1,nick2,...|*]")
			return nil
		}
		data, err := os.ReadFile(parts[1])
		if err != nil {
			m.appendSys(errStyle.Render("Cannot read file: " + err.Error()))
			return nil
		}
		id := filepath.Base(parts[1])
		whom := "*"
		if len(parts) >= 3 {
			whom = parts[2]
		}
		fmt.Fprintf(m.rw, "UPL %s %s %d\n%s", id, whom, len(data), data)
		m.rw.Flush()
		m.appendSys(fmt.Sprintf("Uploading '%s' (%d bytes) to %s", id, len(data), whom))
	case "/get":
		if len(parts) != 2 {
			m.appendSys("Usage: /get <alias|uuid>")
			return nil
		}
		id := parts[1]
		if uuid, ok := m.resourceAliases[id]; ok {
			id = uuid
		}
		fmt.Fprintf(m.rw, "GET %s\n", id)
		m.rw.Flush()
	case "/shutdown":
		m.rw.WriteString("SHT\n")
		m.rw.Flush()
	case "/help", "/h":
		m.appendSys(`/status (/s)           Show your status
/list (/l)             Online users
/say (/dm) <nick> <m>  Send a direct message
/upload (/upl) <file> [to]  Upload a file (* or nick1,nick2,...)
/get <alias|uuid>      Download a file
/kick (/k) <nick>      Kick a user
/admin <nick> <0|1>    Set admin (admin only)
/password (/pw) <pw>   Change your password
/setpass <pw>          Set server password (admin only)
/shutdown              Shut down server (admin only)
/quit (/q)             Disconnect and exit`)
	default:
		m.appendSys("Unknown command (try /help)")
	}
	return nil
}

// Message helpers

func (m *model) appendMsg(origin, content string) {
	content = strings.TrimRight(content, "\n")
	var line string
	switch origin {
	case "__MOTD__":
		line = motdStyle.Render(content)
	case "__SERVER__":
		line = serverStyle.Render(content)
	default:
		line = nickStyle.Render("<"+origin+">") + " " + content
	}
	m.messages = append(m.messages, line)
	m.refreshViewport()
}

func (m *model) appendDm(whom, content string) {
	content = strings.TrimRight(content, "\n")
	line := dmStyle.Render("[DM]") +
				nickStyle.Render("<" + whom + ">") +
				" " + content
	m.messages = append(m.messages, line)
	m.refreshViewport()
}

func (m *model) appendSys(msg string) {
	m.messages = append(m.messages, infoStyle.Render("* "+msg))
	m.refreshViewport()
}

func (m *model) refreshViewport() {
	if !m.ready {
		return
	}
	atBottom := m.viewport.AtBottom()
	w := m.width
	if w <= 0 {
		m.viewport.SetContent(strings.Join(m.messages, "\n"))
	} else {
		wrap := lipgloss.NewStyle().Width(w)
		var wrapped []string
		for _, msg := range m.messages {
			wrapped = append(wrapped, wrap.Render(msg))
		}
		m.viewport.SetContent(strings.Join(wrapped, "\n"))
	}
	if atBottom || len(m.messages) <= m.viewport.Height {
		m.viewport.GotoBottom()
	}
}

// View

func (m model) View() string {
	if m.quitting {
		return ""
	}
	switch m.state {
	case stateLogin, stateConnecting, statePassword, stateError:
		return m.viewLogin()
	case stateChat:
		return m.viewChat()
	}
	return ""
}

func (m model) viewLogin() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	wrap := lipgloss.NewStyle().Width(w)

	var b strings.Builder

	b.WriteString("\n" + titleStyle.Render("ssrpi") + "\n" +
		wrap.Render(infoStyle.Render(
		"  ssrpi-client Copyleft (C) 2026\n" +
    	"  This program comes with ABSOLUTELY NO WARRANTY.\n" +
    	"  This is free software, and you are welcome to redistribute it\n" +
    	"  under certain conditions; see LICENSE for details")) + "\n\n",
	)

	for _, e := range m.loginEntries {
		b.WriteString(e.render() + "\n")
	}

	switch m.state {
	case stateLogin:
		info := stepInfo[m.loginStep]
		b.WriteString("  " + labelStyle.Render(info.label) + "\n")
		b.WriteString(m.loginInput.View() + "\n")

	case stateConnecting:
		b.WriteString("\n  " + infoStyle.Render("Connecting...") + "\n")

	case stateError:
		b.WriteString("\n" + wrap.Render("  " + errStyle.Render("Error: "+m.loginErr)) + "\n")
		b.WriteString("  " + infoStyle.Render("Press any key to exit") + "\n")

	case statePassword:
		if m.isNewUser {
			b.WriteString("\n  " + labelStyle.Render("Create a password") + "\n")
		} else {
			b.WriteString("\n  " + labelStyle.Render("Password") + "\n")
		}
		b.WriteString(m.loginInput.View() + "\n")
	}

	return b.String()
}

func (m model) viewChat() string {
	if !m.ready {
		return infoStyle.Render(" Connecting...")
	}

	status := "connected as " + m.nick
	if !m.connected {
		status = errStyle.Render("disconnected")
	}

	header := lipgloss.NewStyle().Width(m.width).Render(
		titleStyle.Render(" ssrpi") + " " + infoStyle.Render(status))
	sep := separatorStyle.Render(strings.Repeat("─", m.width))

	return header + "\n" + sep + "\n" + m.viewport.View() + "\n" + m.chatInput.View()
}

// Protocol helpers

func readLine(rw *bufio.ReadWriter) (string, error) {
	line, _, err := rw.ReadLine()
	return string(line), err
}

func writeLine(rw *bufio.ReadWriter, s string) {
	rw.WriteString(s + "\n")
	rw.Flush()
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' || r == '\x00' {
			return '_'
		}
		return r
	}, name)
}

// Main
func main() {
	server := flag.String("server", "", "Server address (host:port)")
	servpass := flag.String("servpass", "", "Server password")
	nick := flag.String("nick", "", "Nickname")
	userpass := flag.String("pass", "", "User password")
	flag.Parse()

	p := tea.NewProgram(
		newModel(*server, *servpass, *nick, *userpass),
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
