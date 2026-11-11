package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Config est la configuration du serveur. Les valeurs par défaut sont
// volontairement strictes : TLS obligatoire, authentification obligatoire.
type Config struct {
	Name         string `json:"name"`           // nom du serveur (apparaît dans les préfixes)
	Network      string `json:"network"`        // nom du réseau (ISUPPORT)
	Listen       string `json:"listen"`         // adresse d'écoute TLS
	CertFile     string `json:"cert_file"`      // certificat PEM (auto-généré s'il n'existe pas)
	KeyFile      string `json:"key_file"`       // clé privée PEM
	UsersFile    string `json:"users_file"`     // base des comptes (hash PBKDF2)
	MOTDFile     string `json:"motd_file"`      // message du jour (optionnel)
	RequireAuth  bool   `json:"require_auth"`   // refuse les clients non authentifiés
	MaxClients   int    `json:"max_clients"`    // connexions simultanées maximum
	MaxPerIP     int    `json:"max_per_ip"`     // connexions simultanées par IP
	MaxChannels  int    `json:"max_channels"`   // salons existants maximum
	CloakSecret  string `json:"cloak_secret"`   // secret HMAC de masquage d'IP (aléatoire si vide)
	PingInterval int    `json:"ping_interval"`  // secondes d'inactivité avant PING
	RegTimeout   int    `json:"reg_timeout"`    // secondes allouées pour s'enregistrer
	AuthMaxFails int    `json:"auth_max_fails"` // échecs d'auth avant blocage de l'IP
}

func DefaultConfig() Config {
	return Config{
		Name:         "zinc.local",
		Network:      "Zinc",
		Listen:       ":6697",
		CertFile:     "zinc.crt",
		KeyFile:      "zinc.key",
		UsersFile:    "users.json",
		RequireAuth:  true,
		MaxClients:   1000,
		MaxPerIP:     5,
		MaxChannels:  2000,
		PingInterval: 90,
		RegTimeout:   30,
		AuthMaxFails: 8,
	}
}

// LoadConfig lit un fichier JSON par-dessus les valeurs par défaut.
// Un chemin vide ou inexistant donne la configuration par défaut.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("lecture de la config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // une faute de frappe de sécurité ne doit pas passer en silence
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config invalide: %w", err)
	}
	if cfg.MaxClients < 1 || cfg.MaxPerIP < 1 || cfg.PingInterval < 5 || cfg.RegTimeout < 5 || cfg.AuthMaxFails < 1 {
		return cfg, fmt.Errorf("config invalide: valeurs numériques hors limites")
	}
	return cfg, nil
}
