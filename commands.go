package main

import (
	"crypto/subtle"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"
)

type handler struct {
	fn      func(*Server, *Client, *Message)
	pre     bool // autorisé avant l'enregistrement
	noLock  bool // gère lui-même s.mu (opérations lentes comme PBKDF2)
	minArgs int
}

var handlers map[string]handler

func init() {
	handlers = map[string]handler{
		"CAP":          {(*Server).cmdCap, true, false, 1},
		"PASS":         {(*Server).cmdPass, true, true, 1},
		"AUTHENTICATE": {(*Server).cmdAuthenticate, true, true, 1},
		"NICK":         {(*Server).cmdNick, true, false, 1},
		"USER":         {(*Server).cmdUser, true, false, 4},
		"PING":         {(*Server).cmdPing, true, false, 1},
		"PONG":         {func(*Server, *Client, *Message) {}, true, false, 0},
		"QUIT":         {(*Server).cmdQuit, true, false, 0},
		"JOIN":         {(*Server).cmdJoin, false, false, 1},
		"PART":         {(*Server).cmdPart, false, false, 1},
		"PRIVMSG":      {(*Server).cmdPrivmsg, false, false, 0},
		"NOTICE":       {(*Server).cmdPrivmsg, false, false, 0},
		"TOPIC":        {(*Server).cmdTopic, false, false, 1},
		"NAMES":        {(*Server).cmdNames, false, false, 0},
		"LIST":         {(*Server).cmdList, false, false, 0},
		"WHO":          {(*Server).cmdWho, false, false, 1},
		"WHOIS":        {(*Server).cmdWhois, false, false, 1},
		"MODE":         {(*Server).cmdMode, false, false, 1},
		"KICK":         {(*Server).cmdKick, false, false, 2},
		"INVITE":       {(*Server).cmdInvite, false, false, 2},
		"AWAY":         {(*Server).cmdAway, false, false, 0},
		"MOTD":         {func(s *Server, c *Client, _ *Message) { s.sendMOTD(c) }, false, false, 0},
		"OPER":         {(*Server).cmdOper, false, true, 2},
		"KILL":         {(*Server).cmdKill, false, false, 2},
		"REHASH":       {(*Server).cmdRehash, false, true, 0},
		"DIE":          {(*Server).cmdDie, false, false, 0},
		"WALLOPS":      {(*Server).cmdWallops, false, false, 1},
		"KLINE":        {(*Server).cmdKline, false, false, 1},
		"UNKLINE":      {(*Server).cmdUnkline, false, false, 1},
		"LUSERS":       {(*Server).cmdLusers, false, false, 0},
		"VERSION":      {(*Server).cmdVersion, false, false, 0},
		"TIME":         {(*Server).cmdTime, false, false, 0},
		"INFO":         {(*Server).cmdInfo, false, false, 0},
		"ADMIN":        {(*Server).cmdAdmin, false, false, 0},
		"USERHOST":     {(*Server).cmdUserhost, false, false, 1},
		"ISON":         {(*Server).cmdIson, false, false, 1},
		"PASSWD":       {(*Server).cmdPasswd, false, true, 2},
		"KNOCK":        {(*Server).cmdKnock, false, false, 1},
	}
}

func (s *Server) dispatch(c *Client, m *Message) {
	h, ok := handlers[m.Cmd]
	if !ok {
		if c.isRegistered() {
			c.numeric("421", m.Cmd, "Unknown command")
		}
		return
	}
	if !h.pre && !c.isRegistered() {
		c.numeric("451", "You have not registered")
		return
	}
	if len(m.Params) < h.minArgs {
		c.numeric("461", m.Cmd, "Not enough parameters")
		return
	}
	if !h.noLock {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	h.fn(s, c, m)
}

// ---------- Enregistrement, CAP, SASL ----------

func (s *Server) cmdCap(c *Client, m *Message) {
	switch strings.ToUpper(m.Param(0)) {
	case "LS":
		c.capNegotiating = !c.registered
		c.send(":%s CAP %s LS :sasl=PLAIN,EXTERNAL %s", s.cfg.Name, c.nickOr(), strings.Join(supportedCaps, " "))
	case "LIST":
		var on []string
		for k, v := range c.caps {
			if v {
				on = append(on, k)
			}
		}
		sort.Strings(on)
		c.send(":%s CAP %s LIST :%s", s.cfg.Name, c.nickOr(), strings.Join(on, " "))
	case "REQ":
		reqs := strings.Fields(m.Param(1))
		ok := len(reqs) > 0
		for _, r := range reqs {
			if !isSupportedCap(strings.TrimPrefix(r, "-")) {
				ok = false
			}
		}
		if ok {
			for _, r := range reqs {
				c.caps[strings.TrimPrefix(r, "-")] = !strings.HasPrefix(r, "-")
			}
			c.send(":%s CAP %s ACK :%s", s.cfg.Name, c.nickOr(), m.Param(1))
		} else {
			c.send(":%s CAP %s NAK :%s", s.cfg.Name, c.nickOr(), m.Param(1))
		}
	case "END":
		c.capNegotiating = false
		s.tryRegister(c)
	default:
		c.numeric("410", m.Param(0), "Invalid CAP command")
	}
}

var supportedCaps = []string{"away-notify", "echo-message", "extended-join", "multi-prefix", "server-time"}

func isSupportedCap(n string) bool {
	if n == "sasl" {
		return true
	}
	for _, k := range supportedCaps {
		if k == n {
			return true
		}
	}
	return false
}

// cmdPass : "PASS compte:motdepasse" (alternative à SASL pour les vieux clients).
func (s *Server) cmdPass(c *Client, m *Message) {
	if c.isRegistered() {
		c.numeric("462", "You may not reregister")
		return
	}
	acct, pw, ok := strings.Cut(strings.Join(m.Params, " "), ":")
	if !ok {
		c.numeric("464", "Password must be account:password")
		return
	}
	s.authenticate(c, acct, pw, func() { c.passAuthed = true }, func() {
		c.numeric("464", "Password incorrect")
		c.shutdown("Authentication failed")
	})
}

func (s *Server) cmdAuthenticate(c *Client, m *Message) {
	arg := m.Param(0)
	fail := func(num, msg string) {
		c.saslMech, c.saslBuf = "", ""
		c.numeric(num, msg)
	}
	if c.isRegistered() || !c.caps["sasl"] {
		fail("904", "SASL authentication failed")
		return
	}
	if arg == "*" {
		fail("906", "SASL authentication aborted")
		return
	}
	if c.saslMech == "" {
		mech := strings.ToUpper(arg)
		if mech != "PLAIN" && mech != "EXTERNAL" {
			c.numeric("908", "PLAIN,EXTERNAL", "are available SASL mechanisms")
			fail("904", "SASL authentication failed")
			return
		}
		c.saslMech, c.saslBuf = mech, ""
		c.send("AUTHENTICATE +")
		return
	}
	if arg != "+" {
		c.saslBuf += arg
	}
	if len(c.saslBuf) > 1024 {
		fail("905", "SASL message too long")
		return
	}
	if len(arg) == 400 { // fragment : on attend la suite
		return
	}
	mech, payload := c.saslMech, c.saslBuf
	c.saslMech, c.saslBuf = "", ""
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		c.numeric("904", "SASL authentication failed")
		return
	}
	onOK := func() {
		s.mu.Lock()
		nick := c.nickOr()
		s.mu.Unlock()
		c.numeric("900", nick+"!*@"+c.host, c.account, "You are now logged in as "+c.account)
		c.numeric("903", "SASL authentication successful")
	}
	onFail := func() {
		c.numeric("904", "SASL authentication failed")
		if c.authFails++; c.authFails >= 3 {
			c.shutdown("Too many authentication failures")
		}
	}
	if mech == "EXTERNAL" {
		s.mu.Lock()
		acct, ok := s.certfp[c.certfp]
		s.mu.Unlock()
		if c.certfp == "" || !ok || !s.users.Exists(acct) || (len(raw) > 0 && fold(string(raw)) != fold(acct)) {
			onFail()
			return
		}
		s.mu.Lock()
		c.account = fold(acct)
		s.mu.Unlock()
		onOK()
		return
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || (parts[0] != "" && fold(parts[0]) != fold(parts[1])) {
		c.numeric("904", "SASL authentication failed")
		return
	}
	s.authenticate(c, parts[1], parts[2], onOK, onFail)
}

// authenticate vérifie hors verrou (PBKDF2 est lent) puis fixe le compte.
func (s *Server) authenticate(c *Client, acct, pw string, ok, fail func()) {
	if s.throttle.Locked(c.ip) {
		fail()
		return
	}
	if len(acct) > maxNickLen || len(pw) > 256 || !s.users.Verify(acct, pw) {
		s.throttle.Fail(c.ip)
		fail()
		return
	}
	s.throttle.Success(c.ip)
	s.mu.Lock()
	c.account = fold(acct)
	s.mu.Unlock()
	ok()
}

func (s *Server) cmdNick(c *Client, m *Message) {
	nick := m.Param(0)
	if !validNick(nick) {
		c.numeric("432", nick, "Erroneous nickname")
		return
	}
	if o, taken := s.clients[fold(nick)]; taken && o != c {
		c.numeric("433", nick, "Nickname is already in use")
		return
	}
	if c.registered && s.users.Exists(nick) && c.account != fold(nick) {
		c.numeric("433", nick, "Nickname belongs to a registered account")
		return
	}
	if c.nick != "" && s.clients[fold(c.nick)] == c {
		delete(s.clients, fold(c.nick))
	}
	old := c.prefix()
	s.clients[fold(nick)] = c
	c.nick, c.gotNick = nick, true
	if c.registered {
		seen := map[*Client]bool{c: true}
		c.send(":%s NICK :%s", old, nick)
		for _, ch := range c.channels {
			for mm := range ch.members {
				if !seen[mm] {
					seen[mm] = true
					mm.send(":%s NICK :%s", old, nick)
				}
			}
		}
		return
	}
	s.tryRegister(c)
}

func (s *Server) cmdUser(c *Client, m *Message) {
	if c.registered || c.gotUser {
		c.numeric("462", "You may not reregister")
		return
	}
	c.user = "~" + sanitizeIdent(m.Param(0))
	c.real = truncate(m.Param(3), maxRealLen)
	c.gotUser = true
	s.tryRegister(c)
}

// tryRegister finalise l'enregistrement. Appelé avec s.mu tenu.
func (s *Server) tryRegister(c *Client) {
	if c.registered || !c.gotNick || !c.gotUser || c.capNegotiating {
		return
	}
	if s.cfg.RequireAuth && c.account == "" {
		c.numeric("464", "Authentication required (SASL PLAIN or PASS account:password)")
		c.shutdown("Authentication required")
		return
	}
	if s.users.Exists(c.nick) && c.account != fold(c.nick) {
		c.numeric("433", c.nick, "Nickname belongs to a registered account")
		delete(s.clients, fold(c.nick))
		c.nick, c.gotNick = "", false
		return
	}
	c.registered = true
	c.numeric("001", "Welcome to the "+s.cfg.Network+" network, "+c.nick)
	c.numeric("002", "Your host is "+s.cfg.Name+", running zinc")
	c.numeric("003", "This server was created "+s.created.UTC().Format(time.RFC1123))
	c.numeric("004", s.cfg.Name, "zinc-"+version, "o", "bimnRstklov")
	c.numeric("005", "CHANTYPES=#", "PREFIX=(ov)@+", "CHANMODES=b,k,l,imnRst",
		"NICKLEN="+itoa(maxNickLen), "CHANNELLEN="+itoa(maxChanLen), "TOPICLEN="+itoa(maxTopicLen),
		"NETWORK="+s.cfg.Network, "CASEMAPPING=rfc1459", "are supported by this server")
	s.cmdLusers(c, nil)
	s.sendMOTD(c)
}

func (s *Server) sendMOTD(c *Client) {
	if len(s.motd) == 0 {
		c.numeric("422", "MOTD File is missing")
		return
	}
	c.numeric("375", "- "+s.cfg.Name+" Message of the day -")
	for _, l := range s.motd {
		c.numeric("372", "- "+l)
	}
	c.numeric("376", "End of /MOTD command.")
}

func (s *Server) cmdPing(c *Client, m *Message) {
	c.send(":%s PONG %s :%s", s.cfg.Name, s.cfg.Name, m.Param(0))
}

func (s *Server) cmdQuit(c *Client, m *Message) {
	c.shutdown("Quit: " + truncate(m.Param(0), 200))
}

func (s *Server) cmdAway(c *Client, m *Message) {
	c.away = truncate(m.Param(0), 200)
	seen := map[*Client]bool{c: true}
	for _, ch := range c.channels {
		for mm := range ch.members {
			if !seen[mm] && mm.caps["away-notify"] {
				seen[mm] = true
				if c.away == "" {
					mm.send(":%s AWAY", c.prefix())
				} else {
					mm.send(":%s AWAY :%s", c.prefix(), c.away)
				}
			}
		}
	}
	if c.away == "" {
		c.numeric("305", "You are no longer marked as being away")
	} else {
		c.numeric("306", "You have been marked as being away")
	}
}

// ---------- Salons ----------

func (s *Server) cmdJoin(c *Client, m *Message) {
	if m.Param(0) == "0" {
		for _, ch := range c.channels {
			s.part(c, ch, "")
		}
		return
	}
	chans := strings.Split(m.Param(0), ",")
	keys := strings.Split(m.Param(1), ",")
	for i, name := range chans {
		key := ""
		if i < len(keys) {
			key = keys[i]
		}
		s.join(c, name, key)
	}
}

func (s *Server) join(c *Client, name, key string) {
	if !validChannel(name) {
		c.numeric("403", name, "No such channel")
		return
	}
	k := fold(name)
	if c.channels[k] != nil {
		return
	}
	if len(c.channels) >= maxChansEach {
		c.numeric("405", name, "You have joined too many channels")
		return
	}
	ch := s.channels[k]
	if ch == nil {
		if len(s.channels) >= s.cfg.MaxChannels {
			c.numeric("403", name, "Too many channels on this server")
			return
		}
		ch = &Channel{name: name, created: time.Now().Unix(), members: map[*Client]*Member{},
			invites: map[*Client]bool{}}
		for _, m := range s.cfg.DefaultModes {
			switch m {
			case 'i':
				ch.inviteOnly = true
			case 'm':
				ch.moderated = true
			case 'n':
				ch.noExternal = true
			case 'R':
				ch.regOnly = true
			case 's':
				ch.secret = true
			case 't':
				ch.topicLock = true
			}
		}
		ch.members[c] = &Member{op: true} // le créateur est opérateur
		s.channels[k] = ch
	} else {
		switch {
		case ch.isBanned(c) && !ch.invites[c]:
			c.numeric("474", name, "Cannot join channel (+b)")
			return
		case ch.inviteOnly && !ch.invites[c]:
			c.numeric("473", name, "Cannot join channel (+i)")
			return
		case ch.regOnly && c.account == "":
			c.numeric("477", name, "Cannot join channel (+R): you need to be logged in")
			return
		case ch.key != "" && subtle.ConstantTimeCompare([]byte(ch.key), []byte(key)) != 1:
			c.numeric("475", name, "Cannot join channel (+k)")
			return
		case ch.limit > 0 && len(ch.members) >= ch.limit:
			c.numeric("471", name, "Cannot join channel (+l)")
			return
		}
		ch.members[c] = &Member{}
	}
	delete(ch.invites, c)
	c.channels[k] = ch
	acct := c.account
	if acct == "" {
		acct = "*"
	}
	for mm := range ch.members {
		if mm.caps["extended-join"] {
			mm.send(":%s JOIN %s %s :%s", c.prefix(), ch.name, acct, c.real)
		} else {
			mm.send(":%s JOIN %s", c.prefix(), ch.name)
		}
	}
	if ch.topic != "" {
		s.sendTopic(c, ch)
	}
	s.sendNames(c, ch)
	if c.caps["server-time"] {
		for _, e := range ch.history {
			c.sendAt(e.t, "%s", e.line)
		}
	}
}

func (s *Server) cmdPart(c *Client, m *Message) {
	for _, name := range strings.Split(m.Param(0), ",") {
		ch := c.channels[fold(name)]
		if ch == nil {
			c.numeric("442", name, "You're not on that channel")
			continue
		}
		s.part(c, ch, truncate(m.Param(1), 200))
	}
}

func (s *Server) part(c *Client, ch *Channel, reason string) {
	if reason != "" {
		ch.broadcast(nil, ":%s PART %s :%s", c.prefix(), ch.name, reason)
	} else {
		ch.broadcast(nil, ":%s PART %s", c.prefix(), ch.name)
	}
	delete(ch.members, c)
	delete(c.channels, fold(ch.name))
	s.dropIfEmpty(fold(ch.name), ch)
}

func (s *Server) cmdPrivmsg(c *Client, m *Message) {
	cmd := m.Cmd
	if len(m.Params) == 0 {
		c.numeric("411", "No recipient given ("+cmd+")")
		return
	}
	if len(m.Params) < 2 || m.Params[1] == "" {
		c.numeric("412", "No text to send")
		return
	}
	targets := strings.Split(m.Params[0], ",")
	if len(targets) > maxMsgTargets {
		c.numeric("407", m.Params[0], "Too many recipients")
		return
	}
	text := m.Params[1]
	for _, t := range targets {
		if strings.HasPrefix(t, "#") {
			ch := s.channels[fold(t)]
			if ch == nil {
				c.numeric("403", t, "No such channel")
				continue
			}
			mem := ch.members[c]
			if (mem == nil && ch.noExternal) || (ch.moderated && (mem == nil || !mem.op && !mem.voice)) ||
				(mem != nil && !mem.op && !mem.voice && ch.isBanned(c)) {
				c.numeric("404", ch.name, "Cannot send to channel")
				continue
			}
			line := sprintf(":%s %s %s :%s", c.prefix(), cmd, ch.name, text)
			ch.broadcast(c, "%s", line)
			if c.caps["echo-message"] {
				c.send("%s", line)
			}
			ch.addHistory(s.history, line)
			continue
		}
		dst := s.clients[fold(t)]
		if dst == nil || !dst.registered {
			c.numeric("401", t, "No such nick/channel")
			continue
		}
		dst.send(":%s %s %s :%s", c.prefix(), cmd, dst.nick, text)
		if c.caps["echo-message"] {
			c.send(":%s %s %s :%s", c.prefix(), cmd, dst.nick, text)
		}
		if dst.away != "" && cmd == "PRIVMSG" {
			c.numeric("301", dst.nick, dst.away)
		}
	}
}

func (s *Server) sendTopic(c *Client, ch *Channel) {
	if ch.topic == "" {
		c.numeric("331", ch.name, "No topic is set")
		return
	}
	c.numeric("332", ch.name, ch.topic)
	c.numeric("333", ch.name, ch.topicBy, strconv.FormatInt(ch.topicAt, 10))
}

func (s *Server) cmdTopic(c *Client, m *Message) {
	ch := s.channels[fold(m.Param(0))]
	if ch == nil {
		c.numeric("403", m.Param(0), "No such channel")
		return
	}
	mem := ch.members[c]
	if len(m.Params) == 1 {
		if mem == nil && ch.secret {
			c.numeric("442", ch.name, "You're not on that channel")
			return
		}
		s.sendTopic(c, ch)
		return
	}
	if mem == nil {
		c.numeric("442", ch.name, "You're not on that channel")
		return
	}
	if ch.topicLock && !mem.op {
		c.numeric("482", ch.name, "You're not channel operator")
		return
	}
	ch.topic, ch.topicBy, ch.topicAt = truncate(m.Params[1], maxTopicLen), c.nick, time.Now().Unix()
	ch.broadcast(nil, ":%s TOPIC %s :%s", c.prefix(), ch.name, ch.topic)
}

func (s *Server) sendNames(c *Client, ch *Channel) {
	sym := "="
	if ch.secret {
		sym = "@"
	}
	var nicks []string
	for mm, mem := range ch.members {
		nicks = append(nicks, memberPrefix(mem, c.caps["multi-prefix"])+mm.nick)
	}
	sort.Strings(nicks)
	var line []string
	size := 0
	flush := func() {
		if len(line) > 0 {
			c.numeric("353", sym, ch.name, strings.Join(line, " "))
			line, size = nil, 0
		}
	}
	for _, n := range nicks {
		if size+len(n) > 300 {
			flush()
		}
		line = append(line, n)
		size += len(n) + 1
	}
	flush()
	c.numeric("366", ch.name, "End of /NAMES list.")
}

func (s *Server) cmdNames(c *Client, m *Message) {
	if m.Param(0) == "" {
		for _, ch := range s.visibleChannels(c) {
			s.sendNames(c, ch)
		}
		return
	}
	for _, name := range strings.Split(m.Param(0), ",") {
		ch := s.channels[fold(name)]
		if ch != nil && (!ch.secret || ch.members[c] != nil) {
			s.sendNames(c, ch)
		} else {
			c.numeric("366", name, "End of /NAMES list.")
		}
	}
}

func (s *Server) visibleChannels(c *Client) []*Channel {
	var out []*Channel
	for _, ch := range s.channels {
		if !ch.secret || ch.members[c] != nil {
			out = append(out, ch)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (s *Server) cmdList(c *Client, m *Message) {
	c.numeric("321", "Channel", "Users  Name")
	for _, ch := range s.visibleChannels(c) {
		c.numeric("322", ch.name, itoa(len(ch.members)), ch.topic)
	}
	c.numeric("323", "End of /LIST")
}

func (s *Server) cmdWho(c *Client, m *Message) {
	mask := m.Param(0)
	if ch := s.channels[fold(mask)]; ch != nil && (!ch.secret || ch.members[c] != nil) {
		for mm, mem := range ch.members {
			s.whoLine(c, ch.name, mm, mem)
		}
	} else if t := s.clients[fold(mask)]; t != nil && t.registered {
		s.whoLine(c, "*", t, nil)
	}
	c.numeric("315", mask, "End of /WHO list.")
}

func (s *Server) whoLine(c *Client, chName string, t *Client, mem *Member) {
	flags := "H"
	if t.away != "" {
		flags = "G"
	}
	if t.oper {
		flags += "*"
	}
	if mem != nil {
		flags += memberPrefix(mem, c.caps["multi-prefix"])
	}
	c.numeric("352", chName, t.user, t.host, s.cfg.Name, t.nick, flags, "0 "+t.real)
}

func (s *Server) cmdWhois(c *Client, m *Message) {
	nick := m.Params[len(m.Params)-1]
	t := s.clients[fold(nick)]
	if t == nil || !t.registered {
		c.numeric("401", nick, "No such nick/channel")
		c.numeric("318", nick, "End of /WHOIS list.")
		return
	}
	c.numeric("311", t.nick, t.user, t.host, "*", t.real)
	var chans []string
	for _, ch := range t.channels {
		if !ch.secret || ch.members[c] != nil {
			chans = append(chans, memberPrefix(ch.members[t], c.caps["multi-prefix"])+ch.name)
		}
	}
	sort.Strings(chans)
	if len(chans) > 0 {
		c.numeric("319", t.nick, truncate(strings.Join(chans, " "), 380))
	}
	c.numeric("312", t.nick, s.cfg.Name, s.cfg.Network)
	if t.away != "" {
		c.numeric("301", t.nick, t.away)
	}
	if t.oper {
		c.numeric("313", t.nick, "is an IRC operator")
	}
	if t.account != "" {
		c.numeric("330", t.nick, t.account, "is logged in as")
	}
	c.numeric("318", t.nick, "End of /WHOIS list.")
}

func (s *Server) cmdKick(c *Client, m *Message) {
	ch := s.channels[fold(m.Param(0))]
	if ch == nil {
		c.numeric("403", m.Param(0), "No such channel")
		return
	}
	if mem := ch.members[c]; mem == nil {
		c.numeric("442", ch.name, "You're not on that channel")
		return
	} else if !mem.op {
		c.numeric("482", ch.name, "You're not channel operator")
		return
	}
	t := s.clients[fold(m.Param(1))]
	if t == nil || ch.members[t] == nil {
		c.numeric("441", m.Param(1), "They aren't on that channel")
		return
	}
	reason := truncate(m.Param(2), 200)
	if reason == "" {
		reason = c.nick
	}
	ch.broadcast(nil, ":%s KICK %s %s :%s", c.prefix(), ch.name, t.nick, reason)
	delete(ch.members, t)
	delete(t.channels, fold(ch.name))
	s.dropIfEmpty(fold(ch.name), ch)
}

func (s *Server) cmdInvite(c *Client, m *Message) {
	t := s.clients[fold(m.Param(0))]
	if t == nil || !t.registered {
		c.numeric("401", m.Param(0), "No such nick/channel")
		return
	}
	ch := s.channels[fold(m.Param(1))]
	if ch == nil {
		c.numeric("403", m.Param(1), "No such channel")
		return
	}
	mem := ch.members[c]
	switch {
	case mem == nil:
		c.numeric("442", ch.name, "You're not on that channel")
	case ch.inviteOnly && !mem.op:
		c.numeric("482", ch.name, "You're not channel operator")
	case ch.members[t] != nil:
		c.numeric("443", t.nick, ch.name, "is already on channel")
	default:
		ch.invites[t] = true
		c.numeric("341", t.nick, ch.name)
		t.send(":%s INVITE %s %s", c.prefix(), t.nick, ch.name)
	}
}

func (s *Server) cmdMode(c *Client, m *Message) {
	target := m.Param(0)
	if !strings.HasPrefix(target, "#") {
		if fold(target) != fold(c.nick) {
			c.numeric("502", "Cannot change mode for other users")
			return
		}
		if len(m.Params) > 1 && strings.HasPrefix(m.Params[1], "-") && strings.Contains(m.Params[1], "o") {
			c.oper = false
			c.send(":%s MODE %s :-o", c.nick, c.nick)
			return
		}
		if c.oper {
			c.numeric("221", "+o")
		} else {
			c.numeric("221", "+")
		}
		return
	}
	ch := s.channels[fold(target)]
	if ch == nil {
		c.numeric("403", target, "No such channel")
		return
	}
	mem := ch.members[c]
	if len(m.Params) == 1 {
		if mem == nil && ch.secret {
			c.numeric("442", ch.name, "You're not on that channel")
			return
		}
		c.numeric("324", ch.name, ch.modeString(mem != nil))
		c.numeric("329", ch.name, strconv.FormatInt(ch.created, 10))
		return
	}
	if mem == nil {
		c.numeric("442", ch.name, "You're not on that channel")
		return
	}
	if len(m.Params) == 2 && strings.TrimLeft(m.Params[1], "+") == "b" {
		for _, b := range ch.bans {
			c.numeric("367", ch.name, b)
		}
		c.numeric("368", ch.name, "End of channel ban list")
		return
	}
	if !mem.op {
		c.numeric("482", ch.name, "You're not channel operator")
		return
	}
	var modes strings.Builder
	var args []string
	add := true
	argi := 2
	next := func() (string, bool) {
		if argi < len(m.Params) {
			argi++
			return m.Params[argi-1], true
		}
		return "", false
	}
	sign := byte(0)
	emit := func(on bool, mode byte, arg string) {
		want := byte('-')
		if on {
			want = '+'
		}
		if sign != want {
			modes.WriteByte(want)
			sign = want
		}
		modes.WriteByte(mode)
		if arg != "" {
			args = append(args, arg)
		}
	}
	count := 0
	for _, f := range m.Params[1] {
		if f == '+' || f == '-' {
			add = f == '+'
			continue
		}
		if count++; count > 20 {
			break
		}
		switch f {
		case 'i':
			ch.inviteOnly = add
			emit(add, 'i', "")
		case 'm':
			ch.moderated = add
			emit(add, 'm', "")
		case 'n':
			ch.noExternal = add
			emit(add, 'n', "")
		case 'R':
			ch.regOnly = add
			emit(add, 'R', "")
		case 's':
			ch.secret = add
			emit(add, 's', "")
		case 'b':
			mask, ok := next()
			if !ok {
				for _, b := range ch.bans {
					c.numeric("367", ch.name, b)
				}
				c.numeric("368", ch.name, "End of channel ban list")
				continue
			}
			mask = normalizeMask(mask)
			idx := -1
			for i, b := range ch.bans {
				if b == mask {
					idx = i
				}
			}
			if add && idx < 0 {
				if len(ch.bans) >= 50 {
					c.numeric("478", ch.name, mask, "Channel ban list is full")
					continue
				}
				ch.bans = append(ch.bans, mask)
				emit(true, 'b', mask)
			} else if !add && idx >= 0 {
				ch.bans = append(ch.bans[:idx], ch.bans[idx+1:]...)
				emit(false, 'b', mask)
			}
		case 't':
			ch.topicLock = add
			emit(add, 't', "")
		case 'k':
			if add {
				k, ok := next()
				if !ok || len(k) > maxKeyLen || strings.Contains(k, ",") {
					continue
				}
				ch.key = k
				emit(true, 'k', k)
			} else {
				ch.key = ""
				emit(false, 'k', "*")
			}
		case 'l':
			if add {
				a, ok := next()
				n, err := strconv.Atoi(a)
				if !ok || err != nil || n < 1 || n > 100000 {
					continue
				}
				ch.limit = n
				emit(true, 'l', a)
			} else {
				ch.limit = 0
				emit(false, 'l', "")
			}
		case 'o', 'v':
			nick, ok := next()
			t := s.clients[fold(nick)]
			if !ok || t == nil || ch.members[t] == nil {
				c.numeric("441", nick, "They aren't on that channel")
				continue
			}
			if f == 'o' {
				ch.members[t].op = add
			} else {
				ch.members[t].voice = add
			}
			emit(add, byte(f), t.nick)
		default:
			c.numeric("472", string(f), "is unknown mode char to me")
		}
	}
	if modes.Len() > 0 {
		ch.broadcast(nil, ":%s MODE %s %s %s", c.prefix(), ch.name, modes.String(), strings.Join(args, " "))
	}
}
