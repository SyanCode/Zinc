package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Member struct{ op, voice bool }

type Channel struct {
	name                                                          string
	topic                                                         string
	topicBy                                                       string
	topicAt                                                       int64
	created                                                       int64
	members                                                       map[*Client]*Member
	invites                                                       map[*Client]bool
	bans                                                          []string
	history                                                       []histEntry
	key                                                           string
	limit                                                         int
	inviteOnly, moderated, noExternal, topicLock, secret, regOnly bool
}

type histEntry struct {
	t    time.Time
	line string
}

type Server struct {
	cfg      Config
	users    *UserStore
	throttle *authThrottle
	tlsCfg   *tls.Config
	cloakKey []byte
	motd     []string
	created  time.Time
	cfgPath  string
	connRate *rateLimiter

	// Rechargés par REHASH/SIGHUP ; protégés par mu.
	opers   map[string]string
	certfp  map[string]string
	klines  map[string]string
	history int

	mu       sync.Mutex // protège tout l'état ci-dessous et les champs partagés des clients
	clients  map[string]*Client
	channels map[string]*Channel
	perIP    map[string]int
	total    int

	ln net.Listener
	wg sync.WaitGroup
}

func NewServer(cfg Config) (*Server, error) {
	users, err := LoadUsers(cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := LoadTLS(cfg)
	if err != nil {
		return nil, err
	}
	key := []byte(cfg.CloakSecret)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	s := &Server{
		cfg: cfg, users: users, tlsCfg: tlsCfg, cloakKey: key,
		throttle: newAuthThrottle(cfg.AuthMaxFails),
		connRate: newRateLimiter(cfg.ConnectRate),
		klines:   map[string]string{},
		created:  time.Now(),
		clients:  map[string]*Client{}, channels: map[string]*Channel{}, perIP: map[string]int{},
	}
	s.applyDynamic(cfg)
	return s, nil
}

// applyDynamic (re)charge ce qui peut changer sans redémarrage.
// Appelé sans verrou à l'initialisation, avec s.mu tenu ensuite.
func (s *Server) applyDynamic(cfg Config) {
	s.opers, s.certfp, s.history = cfg.Opers, cfg.CertFP, cfg.HistoryLines
	s.cfg.AdminName, s.cfg.AdminEmail = cfg.AdminName, cfg.AdminEmail
	s.motd = nil
	if cfg.MOTDFile != "" {
		if data, err := os.ReadFile(cfg.MOTDFile); err == nil {
			for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
				s.motd = append(s.motd, truncate(cleanText(l), 400))
			}
		}
	}
}

// Rehash recharge comptes, opérateurs, empreintes, MOTD et historique.
func (s *Server) Rehash() error {
	if err := s.users.Reload(); err != nil {
		return err
	}
	cfg := s.cfg
	if s.cfgPath != "" {
		var err error
		if cfg, err = LoadConfig(s.cfgPath); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyDynamic(cfg)
	return nil
}

// cloak masque l'IP : HMAC tronqué, non réversible sans le secret.
func (s *Server) cloak(ip string) string {
	h := hmac.New(sha256.New, s.cloakKey)
	h.Write([]byte(ip))
	return "zn-" + hex.EncodeToString(h.Sum(nil))[:12] + ".cloak"
}

// Listen ouvre le port TLS. Aucun port en clair n'existe.
func (s *Server) Listen() error {
	ln, err := tls.Listen("tcp", s.cfg.Listen, s.tlsCfg)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.clients {
		c.shutdown("Server shutting down")
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	s.mu.Lock()
	banned := s.klined(ip)
	if banned || s.total >= s.cfg.MaxClients || s.perIP[ip] >= s.cfg.MaxPerIP || !s.connRate.Allow(ip) {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.total++
	s.perIP[ip]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.total--
		if s.perIP[ip]--; s.perIP[ip] <= 0 {
			delete(s.perIP, ip)
		}
		s.mu.Unlock()
	}()

	c := newClient(s, conn, ip)
	go c.writeLoop()
	c.readLoop()
}

// removeClient nettoie l'état après déconnexion.
func (s *Server) removeClient(c *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.nick != "" && s.clients[fold(c.nick)] == c {
		delete(s.clients, fold(c.nick))
	}
	if c.registered {
		reason := truncate(cleanText(c.quitMsg), 200)
		if reason == "" {
			reason = "Connection closed"
		}
		seen := map[*Client]bool{c: true}
		for _, ch := range c.channels {
			for m := range ch.members {
				if !seen[m] {
					seen[m] = true
					m.send(":%s QUIT :%s", c.prefix(), reason)
				}
			}
		}
	}
	for name, ch := range c.channels {
		delete(ch.members, c)
		s.dropIfEmpty(name, ch)
	}
	for _, ch := range s.channels {
		delete(ch.invites, c)
	}
	c.channels = map[string]*Channel{}
}

func (s *Server) dropIfEmpty(key string, ch *Channel) {
	if len(ch.members) == 0 {
		delete(s.channels, key)
	}
}

// klined indique si l'IP correspond à un K-line. s.mu tenu.
func (s *Server) klined(ip string) bool {
	for pat := range s.klines {
		if wildMatch(pat, ip) {
			return true
		}
	}
	return false
}

func (ch *Channel) addHistory(n int, line string) {
	if n <= 0 {
		return
	}
	ch.history = append(ch.history, histEntry{time.Now(), line})
	if len(ch.history) > n {
		ch.history = ch.history[len(ch.history)-n:]
	}
}

// isBanned : les masques sont comparés à nick!user@hôte-masqué ; "$a" / "$a:compte" ciblent les comptes.
func (ch *Channel) isBanned(c *Client) bool {
	for _, b := range ch.bans {
		switch {
		case b == "$a":
			if c.account != "" {
				return true
			}
		case strings.HasPrefix(b, "$a:"):
			if c.account != "" && wildMatch(b[3:], c.account) {
				return true
			}
		case wildMatch(b, c.prefix()):
			return true
		}
	}
	return false
}

func (ch *Channel) broadcast(except *Client, format string, args ...any) {
	line := sprintf(format, args...)
	for m := range ch.members {
		if m != except {
			m.send("%s", line)
		}
	}
}

func (ch *Channel) modeString(showKey bool) string {
	var b, args strings.Builder
	b.WriteByte('+')
	for _, f := range []struct {
		on bool
		c  byte
	}{{ch.inviteOnly, 'i'}, {ch.moderated, 'm'}, {ch.noExternal, 'n'}, {ch.regOnly, 'R'}, {ch.secret, 's'}, {ch.topicLock, 't'}} {
		if f.on {
			b.WriteByte(f.c)
		}
	}
	if ch.key != "" {
		b.WriteByte('k')
		if showKey {
			args.WriteString(" " + ch.key)
		} else {
			args.WriteString(" *")
		}
	}
	if ch.limit > 0 {
		b.WriteByte('l')
		args.WriteString(" " + itoa(ch.limit))
	}
	return b.String() + args.String()
}
