package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxPbkdf2Iter  = 10_000_000
	minPasswordLen = 10
)

var b64 = base64.RawStdEncoding

// pbkdf2Iter : recommandation OWASP pour PBKDF2-HMAC-SHA256 (variable pour les tests).
var pbkdf2Iter = 600_000

// HashPassword produit "pbkdf2-sha256$iter$sel$hash".
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashWith(pw, salt, pbkdf2Iter)
}

func hashWith(pw string, salt []byte, iter int) (string, error) {
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, b64.EncodeToString(salt), b64.EncodeToString(dk)), nil
}

// verifyHash compare en temps constant.
func verifyHash(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > maxPbkdf2Iter {
		return false
	}
	salt, err1 := b64.DecodeString(parts[2])
	want, err2 := b64.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// UserStore est la base des comptes, persistée en JSON (0600).
type UserStore struct {
	path  string
	mu    sync.RWMutex
	users map[string]string // nom replié -> hash
	dummy string            // hash factice : égalise le temps pour les comptes inconnus
	sem   chan struct{}     // borne les calculs PBKDF2 simultanés (anti-DoS CPU)
}

func LoadUsers(path string) (*UserStore, error) {
	u := &UserStore{path: path, users: map[string]string{}, sem: make(chan struct{}, 4)}
	var err error
	if u.dummy, err = HashPassword("dummy-password-for-timing"); err != nil {
		return nil, err
	}
	return u, u.Reload()
}

// Reload relit le fichier (appelé sur SIGHUP).
func (u *UserStore) Reload() error {
	data, err := os.ReadFile(u.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("%s: %w", u.path, err)
	}
	u.mu.Lock()
	u.users = m
	u.mu.Unlock()
	return nil
}

func (u *UserStore) Exists(name string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	_, ok := u.users[fold(name)]
	return ok
}

// Verify vérifie un identifiant/mot de passe. Il ne bloque pas indéfiniment :
// si trop de calculs sont en cours, l'échec est renvoyé.
func (u *UserStore) Verify(name, pw string) bool {
	select {
	case u.sem <- struct{}{}:
		defer func() { <-u.sem }()
	case <-time.After(2 * time.Second):
		return false
	}
	u.mu.RLock()
	stored, ok := u.users[fold(name)]
	u.mu.RUnlock()
	if !ok {
		verifyHash(pw, u.dummy)
		return false
	}
	return verifyHash(pw, stored)
}

// VerifyHash vérifie un mot de passe contre un hash arbitraire (opérateurs),
// avec la même borne de concurrence que Verify. Un hash vide vérifie le hash factice.
func (u *UserStore) VerifyHash(pw, stored string) bool {
	select {
	case u.sem <- struct{}{}:
		defer func() { <-u.sem }()
	case <-time.After(2 * time.Second):
		return false
	}
	if stored == "" {
		verifyHash(pw, u.dummy)
		return false
	}
	return verifyHash(pw, stored)
}

func (u *UserStore) Set(name, pw string) error {
	if !validNick(name) {
		return errors.New("nom de compte invalide")
	}
	if len(pw) < minPasswordLen {
		return fmt.Errorf("mot de passe trop court (minimum %d caractères)", minPasswordLen)
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.users[fold(name)] = h
	return u.save()
}

func (u *UserStore) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.users[fold(name)]; !ok {
		return errors.New("compte inconnu")
	}
	delete(u.users, fold(name))
	return u.save()
}

// save écrit atomiquement (fichier temporaire 0600 puis rename).
func (u *UserStore) save() error {
	data, err := json.MarshalIndent(u.users, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.path), ".users-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), u.path)
}

// rateLimiter limite le nombre d'événements par IP sur une fenêtre d'une minute.
type rateLimiter struct {
	mu   sync.Mutex
	max  int
	hits map[string][]time.Time
}

func newRateLimiter(max int) *rateLimiter {
	return &rateLimiter{max: max, hits: map[string][]time.Time{}}
}

func (r *rateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if len(r.hits) > 10000 {
		for k, v := range r.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > time.Minute {
				delete(r.hits, k)
			}
		}
	}
	h := r.hits[ip]
	for len(h) > 0 && now.Sub(h[0]) > time.Minute {
		h = h[1:]
	}
	if len(h) >= r.max {
		r.hits[ip] = h
		return false
	}
	r.hits[ip] = append(h, now)
	return true
}

// authThrottle bloque temporairement les IP qui accumulent les échecs.
type authThrottle struct {
	mu   sync.Mutex
	max  int
	recs map[string]*failRec
}

type failRec struct {
	n     int
	first time.Time
	until time.Time
}

const (
	failWindow = 10 * time.Minute
	failLock   = 10 * time.Minute
)

func newAuthThrottle(max int) *authThrottle {
	return &authThrottle{max: max, recs: map[string]*failRec{}}
}

func (t *authThrottle) Locked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.recs[ip]
	return r != nil && time.Now().Before(r.until)
}

func (t *authThrottle) Fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if len(t.recs) > 10000 { // borne mémoire
		for k, r := range t.recs {
			if now.After(r.until) && now.Sub(r.first) > failWindow {
				delete(t.recs, k)
			}
		}
	}
	r := t.recs[ip]
	if r == nil || now.Sub(r.first) > failWindow {
		r = &failRec{first: now}
		t.recs[ip] = r
	}
	r.n++
	if r.n >= t.max {
		r.until = now.Add(failLock)
	}
}

func (t *authThrottle) Success(ip string) {
	t.mu.Lock()
	delete(t.recs, ip)
	t.mu.Unlock()
}
