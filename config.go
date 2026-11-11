package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	TLS13Only    bool              `json:"tls13_only"`    // refuse TLS 1.2
	ConnectRate  int               `json:"connect_rate"`  // connexions max par IP et par minute
	HistoryLines int               `json:"history_lines"` // lignes rejouées à l'arrivée dans un salon (0 = désactivé)
	LogFile      string            `json:"log_file"`      // journal d'audit (en plus de stderr)
	Opers        map[string]string `json:"opers"`         // opérateurs : nom -> hash (voir "zinc hash")
	CertFP       map[string]string `json:"certfp"`        // SASL EXTERNAL : empreinte SHA-256 du certificat client -> compte
	AdminName    string            `json:"admin_name"`    // commande ADMIN
	AdminEmail   string            `json:"admin_email"`
	DefaultModes string            `json:"default_modes"` // modes appliqués aux nouveaux salons (défaut "nt")
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
		ConnectRate:  20,
		DefaultModes: "nt",
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
	for fp, acct := range cfg.CertFP {
		delete(cfg.CertFP, fp)
		cfg.CertFP[strings.ToLower(strings.ReplaceAll(fp, ":", ""))] = acct
	}
	for _, m := range cfg.DefaultModes {
		if !strings.ContainsRune("imnRst", m) {
			return cfg, fmt.Errorf("config invalide: default_modes ne peut contenir que i m n R s t")
		}
	}
	if cfg.ConnectRate < 1 || cfg.HistoryLines < 0 || cfg.HistoryLines > 200 {
		return cfg, fmt.Errorf("config invalide: connect_rate ou history_lines hors limites")
	}
	if cfg.MaxClients < 1 || cfg.MaxPerIP < 1 || cfg.PingInterval < 5 || cfg.RegTimeout < 5 || cfg.AuthMaxFails < 1 {
		return cfg, fmt.Errorf("config invalide: valeurs numériques hors limites")
	}
	return cfg, nil
}
