package main

import (
	"log"
	"strings"
	"unicode/utf8"
)

const (
	maxLineLen  = 512 // octets, CRLF compris
	maxNickLen  = 30
	maxChanLen  = 50
	maxTopicLen = 300
	maxRealLen  = 100
	maxKeyLen   = 23
)

func logf(format string, args ...any) { log.Printf(format, args...) }

// fold applique la casse IRC (RFC 1459 : []\ ~ {}|^).
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == '[':
			return '{'
		case r == ']':
			return '}'
		case r == '\\':
			return '|'
		}
		return r
	}, s)
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isSpecial(c byte) bool {
	return strings.IndexByte("[]\\`_^{|}", c) >= 0
}

func validNick(n string) bool {
	if n == "" || len(n) > maxNickLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if isLetter(c) || isSpecial(c) || (i > 0 && (isDigit(c) || c == '-')) {
			continue
		}
		return false
	}
	return true
}

func validChannel(n string) bool {
	if len(n) < 2 || len(n) > maxChanLen || n[0] != '#' {
		return false
	}
	if !utf8.ValidString(n) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; c <= ' ' || c == ',' || c == 0x7f {
			return false
		}
	}
	return true
}

// sanitizeIdent ne garde que des caractères sûrs pour le champ "user".
func sanitizeIdent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 10; i++ {
		c := s[i]
		if isLetter(c) || isDigit(c) || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

// cleanText retire les caractères de contrôle dangereux (NUL, CR, LF...)
// en conservant le formatage IRC (^B ^C ^O ^V ^] ^_ et CTCP ^A).
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || r == 0x7f {
			return -1
		}
		if r < 0x20 && !strings.ContainsRune("\x01\x02\x03\x0f\x16\x1d\x1f", r) {
			return -1
		}
		return r
	}, s)
}

// truncate coupe à n octets sans casser un caractère UTF-8.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Message est une ligne IRC analysée.
type Message struct {
	Cmd    string
	Params []string
}

func (m *Message) Param(i int) string {
	if i < len(m.Params) {
		return m.Params[i]
	}
	return ""
}

// parseMessage analyse une ligne (sans CRLF). Tags et préfixe client sont ignorés.
func parseMessage(line string) (*Message, bool) {
	line = cleanText(line)
	skip := func(prefix byte) {
		if len(line) > 0 && line[0] == prefix {
			if i := strings.IndexByte(line, ' '); i >= 0 {
				line = strings.TrimLeft(line[i:], " ")
			} else {
				line = ""
			}
		}
	}
	skip('@')
	skip(':')
	cmd, rest, _ := strings.Cut(line, " ")
	if cmd == "" {
		return nil, false
	}
	m := &Message{Cmd: strings.ToUpper(cmd)}
	for {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" || len(m.Params) >= 15 {
			break
		}
		if rest[0] == ':' {
			m.Params = append(m.Params, rest[1:])
			break
		}
		var p string
		p, rest, _ = strings.Cut(rest, " ")
		m.Params = append(m.Params, p)
	}
	return m, true
}

// wildMatch compare un motif avec * et ? (insensible à la casse IRC).
func wildMatch(pattern, s string) bool {
	p, t := []rune(fold(pattern)), []rune(fold(s))
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi, mark = star+1, mark+1
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// normalizeMask complète un masque de ban : "nick" -> nick!*@*, "u@h" -> *!u@h.
func normalizeMask(m string) string {
	m = cleanText(truncate(m, 100))
	if strings.HasPrefix(m, "$a") {
		return m
	}
	switch {
	case !strings.ContainsAny(m, "!@"):
		return m + "!*@*"
	case !strings.Contains(m, "!"):
		return "*!" + m
	case !strings.Contains(m, "@"):
		return m + "@*"
	}
	return m
}

func memberPrefix(mem *Member, multi bool) string {
	switch {
	case mem.op && mem.voice && multi:
		return "@+"
	case mem.op:
		return "@"
	case mem.voice:
		return "+"
	}
	return ""
}
