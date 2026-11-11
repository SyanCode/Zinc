package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

const usage = `Zinc — serveur IRC sécurisé (TLS obligatoire, comptes PBKDF2, SASL PLAIN)

Usage:
  zinc serve   [-config zinc.json]            lance le serveur
  zinc check   [-config zinc.json]            valide la configuration
  zinc useradd [-config zinc.json] <compte>   crée ou change le mot de passe (lu sur stdin)
  zinc userdel [-config zinc.json] <compte>   supprime un compte
  zinc users   [-config zinc.json]            liste les comptes
  zinc hash                                   hash PBKDF2 d'un mot de passe (pour "opers" dans la config)
  zinc version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "version":
		fmt.Println("zinc", version)
		return
	case "hash":
		h, err := HashPassword(readPassword())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(h)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "", "fichier de configuration JSON")
	fs.Parse(os.Args[2:])
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	switch cmd {
	case "serve":
		serve(cfg, *cfgPath)
	case "check":
		fmt.Println("configuration valide")
	case "users":
		users, err := LoadUsers(cfg.UsersFile)
		if err != nil {
			log.Fatal(err)
		}
		users.mu.RLock()
		var names []string
		for n := range users.users {
			names = append(names, n)
		}
		users.mu.RUnlock()
		sort.Strings(names)
		fmt.Println(strings.Join(names, "\n"))
	case "useradd", "userdel":
		if fs.NArg() != 1 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		users, err := LoadUsers(cfg.UsersFile)
		if err != nil {
			log.Fatal(err)
		}
		if cmd == "userdel" {
			err = users.Delete(fs.Arg(0))
		} else {
			err = users.Set(fs.Arg(0), readPassword())
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// readPassword lit le mot de passe sur stdin, sans écho si c'est un terminal.
func readPassword() string {
	fmt.Fprint(os.Stderr, "Mot de passe: ")
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	tty := off.Run() == nil
	if tty {
		defer func() {
			on := exec.Command("stty", "echo")
			on.Stdin = os.Stdin
			on.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func serve(cfg Config, cfgPath string) {
	if cfg.LogFile != "" {
		lf, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}
	s, err := NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	s.cfgPath = cfgPath
	if err := s.Listen(); err != nil {
		log.Fatal(err)
	}
	logf("Zinc à l'écoute (TLS) sur %s — require_auth=%v", s.Addr(), cfg.RequireAuth)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sg := range sig {
			if sg == syscall.SIGHUP {
				if err := s.Rehash(); err != nil {
					logf("rechargement: %v", err)
				} else {
					logf("configuration rechargée")
				}
				continue
			}
			logf("arrêt")
			s.Close()
			os.Exit(0)
		}
	}()
	s.Serve()
}
