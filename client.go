package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	sendQSize     = 256
	floodBurst    = 20.0 // lignes
	floodRate     = 2.0  // lignes/s
	maxChansEach  = 20
	maxMsgTargets = 4
)

type Client struct {
	srv  *Server
	conn net.Conn
	ip   string
	host string // hôte masqué (jamais l'IP réelle)

	// Champs partagés : protégés par srv.mu.
	nick, user, real string
	account          string
	registered       bool
	channels         map[string]*Channel
	away             string
	oper             bool

	// Champs privés à la goroutine de lecture.
	gotNick, gotUser bool
	capNegotiating   bool
	caps             map[string]bool // capacités IRCv3 activées
	certfp           string          // empreinte SHA-256 du certificat client (si présenté)
	saslMech         string
	saslBuf          string
	saslActive       bool
	passAuthed       bool
	authFails        int
	bucket           float64
	bucketAt         time.Time
	pingSent         bool
	regDeadline      time.Time

	out       chan string
	done      chan struct{}
	closeOnce sync.Once
	quitMsg   string
}

func newClient(s *Server, conn net.Conn, ip string) *Client {
	return &Client{
		srv: s, conn: conn, ip: ip, host: s.cloak(ip),
		channels: map[string]*Channel{}, caps: map[string]bool{},
		out:    make(chan string, sendQSize),
		done:   make(chan struct{}),
		bucket: floodBurst, bucketAt: time.Now(),
	}
}

func (c *Client) prefix() string { return c.nick + "!" + c.user + "@" + c.host }

func (c *Client) nickOr() string {
	if c.nick == "" {
		return "*"
	}
	return c.nick
}

// send met une ligne en file. Jamais bloquant : un client trop lent est déconnecté.
func (c *Client) send(format string, args ...any) { c.sendAt(time.Now(), format, args...) }

// sendAt est send avec un horodatage explicite (rejeu d'historique).
func (c *Client) sendAt(t time.Time, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	line = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, line)
	line = truncate(line, maxLineLen-2)
	if c.caps["server-time"] && strings.HasPrefix(line, ":") {
		line = "@time=" + t.UTC().Format("2006-01-02T15:04:05.000Z") + " " + line
	}
	line += "\r\n"
	select {
	case c.out <- line:
	case <-c.done:
	default:
		c.shutdown("SendQ exceeded")
	}
}

// numeric envoie un numérique ; le dernier argument est le texte final.
func (c *Client) numeric(code string, args ...string) {
	var b strings.Builder
	fmt.Fprintf(&b, ":%s %s %s", c.srv.cfg.Name, code, c.nickOr())
	for i, a := range args {
		if i == len(args)-1 {
			b.WriteString(" :" + a)
		} else {
			b.WriteString(" " + a)
		}
	}
	c.send("%s", b.String())
}

// shutdown ferme la connexion proprement (le nettoyage est fait par readLoop).
func (c *Client) shutdown(reason string) {
	c.closeOnce.Do(func() {
		c.quitMsg = reason
		select {
		case c.out <- "ERROR :Closing Link: " + c.host + " (" + cleanText(reason) + ")\r\n":
		default:
		}
		close(c.done)
	})
}

func (c *Client) writeLoop() {
	defer c.conn.Close()
	write := func(l string) bool {
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := c.conn.Write([]byte(l))
		return err == nil
	}
	for {
		select {
		case l := <-c.out:
			if !write(l) {
				return
			}
		case <-c.done:
			for {
				select {
				case l := <-c.out:
					if !write(l) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// allow applique un seau à jetons anti-flood.
func (c *Client) allow() bool {
	now := time.Now()
	c.bucket += now.Sub(c.bucketAt).Seconds() * floodRate
	if c.bucket > floodBurst {
		c.bucket = floodBurst
	}
	c.bucketAt = now
	if c.bucket < 1 {
		return false
	}
	c.bucket--
	return true
}

func (c *Client) readLoop() {
	s := c.srv
	defer func() {
		c.shutdown("Connection closed")
		s.removeClient(c)
	}()
	tc := c.conn.(*tls.Conn)
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return // client non-TLS ou handshake raté : on coupe sans rien répondre
	}
	if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
		sum := sha256.Sum256(st.PeerCertificates[0].Raw)
		c.certfp = hex.EncodeToString(sum[:])
	}
	c.regDeadline = time.Now().Add(time.Duration(s.cfg.RegTimeout) * time.Second)
	ping := time.Duration(s.cfg.PingInterval) * time.Second
	r := bufio.NewReaderSize(c.conn, 4096)
	for {
		deadline := time.Now().Add(ping)
		if !c.isRegistered() {
			deadline = c.regDeadline
		}
		c.conn.SetReadDeadline(deadline)
		raw, err := r.ReadSlice('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !c.isRegistered() {
					c.shutdown("Registration timeout")
					return
				}
				if !c.pingSent {
					c.pingSent = true
					c.send("PING :%s", s.cfg.Name)
					continue
				}
				c.shutdown("Ping timeout")
				return
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				c.shutdown("Line too long")
			}
			return
		}
		select {
		case <-c.done:
			return
		default:
		}
		c.pingSent = false
		if len(raw) > maxLineLen {
			c.numeric("417", "Input line was too long")
			continue
		}
		if !c.allow() {
			c.shutdown("Excess Flood")
			return
		}
		line := strings.TrimRight(string(raw), "\r\n")
		if line == "" {
			continue
		}
		if m, ok := parseMessage(line); ok {
			s.dispatch(c, m)
		}
	}
}

func (c *Client) isRegistered() bool {
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	return c.registered
}
