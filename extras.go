package main

import (
	"os"
	"sort"
	"strings"
	"time"
)

const version = "1.1.0"

// ---------- Opérateurs ----------

func (s *Server) cmdOper(c *Client, m *Message) {
	name, pw := m.Param(0), m.Param(1)
	s.mu.Lock()
	stored, ok := s.opers[name]
	s.mu.Unlock()
	if s.throttle.Locked(c.ip) || len(pw) > 256 {
		c.numeric("491", "No O-lines for your host")
		return
	}
	if !ok {
		stored = ""
	}
	if !s.users.VerifyHash(pw, stored) {
		s.throttle.Fail(c.ip)
		logf("OPER échoué: %q depuis %s", name, c.host)
		c.numeric("464", "Password incorrect")
		return
	}
	s.mu.Lock()
	c.oper = true
	nick := c.nick
	s.mu.Unlock()
	logf("OPER réussi: %s (%s)", nick, name)
	c.numeric("381", "You are now an IRC operator")
	c.send(":%s MODE %s :+o", nick, nick)
}

// needOper : s.mu tenu.
func (c *Client) needOper() bool {
	if !c.oper {
		c.numeric("481", "Permission Denied- You're not an IRC operator")
		return false
	}
	return true
}

func (s *Server) cmdKill(c *Client, m *Message) {
	if !c.needOper() {
		return
	}
	t := s.clients[fold(m.Param(0))]
	if t == nil || !t.registered {
		c.numeric("401", m.Param(0), "No such nick/channel")
		return
	}
	logf("KILL: %s tue %s (%s)", c.nick, t.nick, m.Param(1))
	t.shutdown("Killed (" + c.nick + " (" + truncate(m.Param(1), 150) + "))")
}

func (s *Server) cmdRehash(c *Client, m *Message) {
	s.mu.Lock()
	ok := c.oper
	s.mu.Unlock()
	if !ok {
		c.numeric("481", "Permission Denied- You're not an IRC operator")
		return
	}
	if err := s.Rehash(); err != nil {
		logf("REHASH échoué: %v", err)
		c.numeric("468", "Rehash failed: see server log")
		return
	}
	logf("REHASH par %s", c.nick)
	c.numeric("382", "zinc.json", "Rehashing")
}

func (s *Server) cmdDie(c *Client, m *Message) {
	if !c.needOper() {
		return
	}
	logf("DIE par %s", c.nick)
	go func() { s.Close(); os.Exit(0) }()
}

func (s *Server) cmdWallops(c *Client, m *Message) {
	if !c.needOper() {
		return
	}
	for _, t := range s.clients {
		if t.oper {
			t.send(":%s WALLOPS :%s", c.prefix(), m.Param(0))
		}
	}
}

// cmdKline : KLINE <motif-ip> [raison] — bannit une IP (jokers * ?) et déconnecte les clients concernés.
func (s *Server) cmdKline(c *Client, m *Message) {
	if !c.needOper() {
		return
	}
	pat := truncate(m.Param(0), 64)
	if strings.Trim(pat, "*?.:") == "" {
		c.numeric("461", "KLINE", "Refusing a pattern that matches everyone")
		return
	}
	reason := truncate(m.Param(1), 100)
	s.klines[pat] = reason
	logf("KLINE %s par %s (%s)", pat, c.nick, reason)
	for _, t := range s.clients {
		if wildMatch(pat, t.ip) && t != c {
			t.shutdown("K-Lined: " + reason)
		}
	}
	c.send(":%s NOTICE %s :K-Line ajouté pour %s", s.cfg.Name, c.nick, pat)
}

func (s *Server) cmdUnkline(c *Client, m *Message) {
	if !c.needOper() {
		return
	}
	if _, ok := s.klines[m.Param(0)]; !ok {
		c.send(":%s NOTICE %s :Aucun K-Line pour %s", s.cfg.Name, c.nick, m.Param(0))
		return
	}
	delete(s.klines, m.Param(0))
	logf("UNKLINE %s par %s", m.Param(0), c.nick)
	c.send(":%s NOTICE %s :K-Line retiré pour %s", s.cfg.Name, c.nick, m.Param(0))
}

// ---------- Informations ----------

func (s *Server) cmdLusers(c *Client, _ *Message) {
	users, opers := 0, 0
	for _, t := range s.clients {
		if t.registered {
			users++
			if t.oper {
				opers++
			}
		}
	}
	c.numeric("251", "There are "+itoa(users)+" users and 0 invisible on 1 servers")
	if opers > 0 {
		c.numeric("252", itoa(opers), "operator(s) online")
	}
	c.numeric("254", itoa(len(s.channels)), "channels formed")
	c.numeric("255", "I have "+itoa(users)+" clients and 0 servers")
}

func (s *Server) cmdVersion(c *Client, _ *Message) {
	c.numeric("351", "zinc-"+version+".", s.cfg.Name, "TLS-only secure IRC")
}

func (s *Server) cmdTime(c *Client, _ *Message) {
	c.numeric("391", s.cfg.Name, time.Now().UTC().Format(time.RFC1123))
}

func (s *Server) cmdInfo(c *Client, _ *Message) {
	for _, l := range []string{"Zinc " + version + " — serveur IRC sécurisé", "TLS obligatoire, SASL, PBKDF2, anti-flood",
		"Démarré le " + s.created.UTC().Format(time.RFC1123)} {
		c.numeric("371", l)
	}
	c.numeric("374", "End of /INFO list")
}

func (s *Server) cmdAdmin(c *Client, _ *Message) {
	c.numeric("256", s.cfg.Name, "Administrative info")
	c.numeric("257", orDash(s.cfg.AdminName))
	c.numeric("258", s.cfg.Network)
	c.numeric("259", orDash(s.cfg.AdminEmail))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (s *Server) cmdUserhost(c *Client, m *Message) {
	var out []string
	for _, n := range m.Params {
		if t := s.clients[fold(n)]; t != nil && t.registered {
			star, away := "", "+"
			if t.oper {
				star = "*"
			}
			if t.away != "" {
				away = "-"
			}
			out = append(out, t.nick+star+"="+away+t.user+"@"+t.host)
		}
		if len(out) >= 5 {
			break
		}
	}
	c.numeric("302", strings.Join(out, " "))
}

func (s *Server) cmdIson(c *Client, m *Message) {
	var out []string
	for _, n := range strings.Fields(strings.Join(m.Params, " ")) {
		if t := s.clients[fold(n)]; t != nil && t.registered {
			out = append(out, t.nick)
		}
	}
	sort.Strings(out)
	c.numeric("303", strings.Join(out, " "))
}

// cmdPasswd : PASSWD <ancien> <nouveau> — change le mot de passe du compte connecté.
func (s *Server) cmdPasswd(c *Client, m *Message) {
	s.mu.Lock()
	acct, reg := c.account, c.registered
	s.mu.Unlock()
	note := func(msg string) { c.send(":%s NOTICE %s :%s", s.cfg.Name, c.nickOr(), msg) }
	if !reg || acct == "" {
		note("Vous devez être connecté à un compte")
		return
	}
	if s.throttle.Locked(c.ip) || !s.users.Verify(acct, m.Param(0)) {
		s.throttle.Fail(c.ip)
		note("Mot de passe actuel incorrect")
		return
	}
	if err := s.users.Set(acct, m.Param(1)); err != nil {
		note("Échec: " + err.Error())
		return
	}
	logf("mot de passe changé pour le compte %s", acct)
	note("Mot de passe changé")
}

// cmdKnock : demande d'invitation, transmise aux opérateurs du salon.
func (s *Server) cmdKnock(c *Client, m *Message) {
	ch := s.channels[fold(m.Param(0))]
	switch {
	case ch == nil || (ch.secret && ch.members[c] == nil):
		c.numeric("403", m.Param(0), "No such channel")
	case ch.members[c] != nil:
		c.numeric("714", ch.name, "You're already on that channel")
	case !ch.inviteOnly:
		c.numeric("480", ch.name, "Channel is open, just join it")
	case ch.isBanned(c):
		c.numeric("474", ch.name, "Cannot knock (+b)")
	default:
		for mm, mem := range ch.members {
			if mem.op {
				mm.send(":%s NOTICE %s :%s demande à rejoindre %s (INVITE %s %s)", s.cfg.Name, ch.name, c.nick, ch.name, c.nick, ch.name)
			}
		}
		c.numeric("711", ch.name, "Your KNOCK has been delivered")
	}
}
