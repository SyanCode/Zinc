package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	pbkdf2Iter = 1000 // tests rapides
	os.Exit(m.Run())
}

func testServer(t *testing.T, requireAuth bool) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.HistoryLines = 10
	cfg.ConnectRate = 1000
	cfg.MaxPerIP = 50
	hash, _ := HashPassword("oper-password")
	cfg.Opers = map[string]string{"root": hash}
	cfg.Listen = "127.0.0.1:0"
	cfg.CertFile = filepath.Join(dir, "c.crt")
	cfg.KeyFile = filepath.Join(dir, "c.key")
	cfg.UsersFile = filepath.Join(dir, "users.json")
	cfg.RequireAuth = requireAuth
	cfg.AuthMaxFails = 100
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.users.Set("alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(s.Close)
	return s
}

type tc struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func dial(t *testing.T, s *Server) *tc {
	c, err := tls.Dial("tcp", s.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &tc{t, c, bufio.NewReader(c)}
}

func (x *tc) send(l string) { x.c.Write([]byte(l + "\r\n")) }

// expect lit jusqu'à trouver une ligne contenant sub.
func (x *tc) expect(sub string) string {
	x.t.Helper()
	x.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		l, err := x.r.ReadString('\n')
		if err != nil {
			x.t.Fatalf("attendu %q, erreur: %v", sub, err)
		}
		if strings.Contains(l, sub) {
			return l
		}
	}
}

func sasl(x *tc, nick, user, pw string) {
	x.send("CAP REQ :sasl")
	x.expect("ACK")
	x.send("AUTHENTICATE PLAIN")
	x.expect("AUTHENTICATE +")
	x.send("AUTHENTICATE " + base64.StdEncoding.EncodeToString([]byte("\x00"+user+"\x00"+pw)))
}

func TestChatFlow(t *testing.T) {
	s := testServer(t, false)
	a, b := dial(t, s), dial(t, s)
	a.send("NICK ann")
	a.send("USER u 0 * :Ann")
	a.expect(" 001 ")
	b.send("NICK bob")
	b.send("USER u 0 * :Bob")
	b.expect(" 001 ")
	a.send("JOIN #test")
	a.expect(" 366 ")
	b.send("JOIN #test")
	b.expect(" 366 ")
	a.expect("JOIN #test") // join de bob
	b.send("PRIVMSG #test :salut")
	l := a.expect("PRIVMSG #test :salut")
	if !strings.Contains(l, "@zn-") || strings.Contains(l, "127.0.0.1") {
		t.Fatalf("l'IP doit être masquée: %q", l)
	}
	// bob n'est pas op : pas de changement de topic (+t)
	b.send("TOPIC #test :pwned")
	b.expect(" 482 ")
	a.send("MODE #test +k secret")
	a.expect("MODE #test +k secret")
}

func TestPlaintextRejected(t *testing.T) {
	s := testServer(t, false)
	c, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("NICK x\r\nUSER x 0 * :x\r\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	if strings.Contains(string(buf[:n]), "001") {
		t.Fatal("le serveur a répondu en clair")
	}
}

func TestAuthRequired(t *testing.T) {
	s := testServer(t, true)
	x := dial(t, s)
	x.send("NICK eve")
	x.send("USER e 0 * :e")
	x.expect(" 464 ")

	y := dial(t, s)
	y.send("CAP LS 302")
	sasl(y, "alice", "alice", "mauvais mot de passe")
	y.expect(" 904 ")

	z := dial(t, s)
	z.send("CAP LS 302")
	sasl(z, "alice", "alice", "correct horse battery")
	z.expect(" 903 ")
	z.send("NICK alice")
	z.send("USER a 0 * :a")
	z.send("CAP END")
	z.expect(" 001 ")
}

func TestReservedNick(t *testing.T) {
	s := testServer(t, false)
	x := dial(t, s)
	x.send("NICK alice")
	x.send("USER a 0 * :a")
	x.expect(" 433 ")
}

func TestPassAuth(t *testing.T) {
	s := testServer(t, true)
	x := dial(t, s)
	x.send("PASS alice:correct horse battery")
	x.send("NICK alice")
	x.send("USER a 0 * :a")
	x.expect(" 001 ")
}

func TestFloodDisconnect(t *testing.T) {
	s := testServer(t, false)
	x := dial(t, s)
	x.send("NICK f")
	x.send("USER f 0 * :f")
	x.expect(" 001 ")
	for i := 0; i < 60; i++ {
		x.send("PING x")
	}
	// Le serveur coupe : ERROR ou reset de connexion (données non lues côté serveur).
	x.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := x.r.ReadString('\n'); err != nil {
			return
		}
	}
}

func TestHashRoundTrip(t *testing.T) {
	h, err := HashPassword("un-mot-de-passe-long")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyHash("un-mot-de-passe-long", h) || verifyHash("autre", h) {
		t.Fatal("vérification de hash incorrecte")
	}
}

func TestParse(t *testing.T) {
	m, ok := parseMessage("@a=b :n!u@h privmsg #c :hello  world")
	if !ok || m.Cmd != "PRIVMSG" || m.Params[1] != "hello  world" {
		t.Fatalf("%+v", m)
	}
	m, _ = parseMessage("PRIVMSG #c :a\x00b\rc")
	if m.Params[1] != "abc" {
		t.Fatalf("caractères de contrôle non filtrés: %q", m.Params[1])
	}
}

func reg(t *testing.T, s *Server, nick string) *tc {
	x := dial(t, s)
	x.send("NICK " + nick)
	x.send("USER u 0 * :" + nick)
	x.expect(" 001 ")
	return x
}

func TestBan(t *testing.T) {
	s := testServer(t, false)
	a, b := reg(t, s, "ann"), reg(t, s, "bob")
	a.send("JOIN #b")
	a.expect(" 366 ")
	a.send("MODE #b +b bob")
	a.expect("+b bob!*@*")
	b.send("JOIN #b")
	b.expect(" 474 ")
	a.send("MODE #b +b")
	a.expect(" 367 ")
	a.send("MODE #b -b bob")
	a.expect("-b bob!*@*")
	b.send("JOIN #b")
	b.expect(" 366 ")
}

func TestRegisteredOnlyChannel(t *testing.T) {
	s := testServer(t, false)
	a, b := reg(t, s, "ann"), reg(t, s, "bob")
	a.send("JOIN #r")
	a.send("MODE #r +R")
	a.expect("MODE #r +R")
	b.send("JOIN #r")
	b.expect(" 477 ")
}

func TestOperKillKline(t *testing.T) {
	s := testServer(t, false)
	o, v := reg(t, s, "opr"), reg(t, s, "vic")
	v.send("KILL opr x")
	v.expect(" 481 ")
	o.send("OPER root mauvais")
	o.expect(" 464 ")
	o.send("OPER root oper-password")
	o.expect(" 381 ")
	o.send("KILL vic spam")
	v.expect("Killed")
	o.send("KLINE 127.0.0.* test")
	o.expect("K-Line ajouté")
	c, err := tls.Dial("tcp", s.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		defer c.Close()
		c.Write([]byte("NICK z\r\nUSER z 0 * :z\r\n"))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, _ := c.Read(make([]byte, 64)); n > 0 {
			t.Fatal("IP klinée acceptée")
		}
	}
	o.send("UNKLINE 127.0.0.*")
	o.expect("K-Line retiré")
}

func TestIRCv3(t *testing.T) {
	s := testServer(t, false)
	a := dial(t, s)
	a.send("CAP LS 302")
	a.expect("multi-prefix")
	a.send("CAP REQ :server-time echo-message multi-prefix")
	a.expect("ACK")
	a.send("CAP REQ :bogus")
	a.expect("NAK")
	a.send("NICK ann")
	a.send("USER u 0 * :ann")
	a.send("CAP END")
	a.expect(" 001 ")
	a.send("JOIN #c")
	a.expect(" 366 ")
	a.send("PRIVMSG #c :hello")
	l := a.expect("PRIVMSG #c :hello") // echo-message
	if !strings.HasPrefix(l, "@time=") {
		t.Fatalf("server-time absent: %q", l)
	}
	// historique rejoué au 2e join
	b := reg(t, s, "bob") // garde le salon (et son historique) en vie
	b.send("JOIN #c")
	b.expect(" 366 ")
	a.send("PART #c")
	a.send("JOIN #c")
	a.expect("PRIVMSG #c :hello")
}

func TestMisc(t *testing.T) {
	s := testServer(t, false)
	a := reg(t, s, "ann")
	a.send("LUSERS")
	a.expect(" 251 ")
	a.send("VERSION")
	a.expect(" 351 ")
	a.send("ISON ann nobody")
	a.expect(" 303 ")
	a.send("USERHOST ann")
	a.expect(" 302 ")
	a.send("KNOCK #nope")
	a.expect(" 403 ")
}

func TestPasswd(t *testing.T) {
	s := testServer(t, true)
	x := dial(t, s)
	x.send("PASS alice:correct horse battery")
	x.send("NICK alice")
	x.send("USER a 0 * :a")
	x.expect(" 001 ")
	x.send("PASSWD mauvais nouveaumotdepasse")
	x.expect("incorrect")
	s.users.Set("alice", "ancien-mot-de-passe")
	x.send("PASSWD ancien-mot-de-passe nouveau-mot-de-passe")
	x.expect("Mot de passe changé")
	if !s.users.Verify("alice", "nouveau-mot-de-passe") {
		t.Fatal("le mot de passe n'a pas changé")
	}
}

func TestWildMatch(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{{"*", "x", true}, {"a*c", "abbc", true}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"*!*@zn-*", "n!u@zn-1.cloak", true}, {"BOB!*@*", "bob!u@h", true}, {"a*b", "ac", false}} {
		if wildMatch(c.p, c.s) != c.ok {
			t.Errorf("wildMatch(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}
