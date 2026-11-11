# Zinc

IRC, mais on a pensé à la sécurité cette fois.

Serveur IRC en Go, **sans aucune dépendance** (bibliothèque standard uniquement), TLS obligatoire.

## Sécurité

- **TLS obligatoire** : aucun port en clair. TLS 1.2 minimum (ECDHE + AEAD uniquement), TLS 1.3 seul avec `tls13_only`. Certificat auto-signé généré au premier lancement (empreinte affichée), ou fournissez le vôtre.
- **Authentification** (`require_auth: true` par défaut) : **SASL PLAIN**, **SASL EXTERNAL** (certificat client, voir `certfp`) ou `PASS compte:motdepasse`.
- **Mots de passe** : PBKDF2-HMAC-SHA256, 600 000 itérations, sel aléatoire, comparaison en temps constant, fichier `0600`, écriture atomique, calculs bornés (anti-DoS CPU), hash factice pour les comptes inconnus.
- **Anti brute-force** : 3 échecs SASL = déconnexion ; trop d'échecs (SASL, PASS, OPER, PASSWD) depuis une IP = blocage 10 min.
- **IP masquées** : les autres ne voient qu'un hôte HMAC (`zn-xxxxxxxxxxxx.cloak`), ident forcé en `~user` assaini.
- **Pseudos protégés** : un pseudo égal à un compte n'est utilisable que par ce compte connecté.
- **Durcissement** : lignes ≤ 512 octets, filtrage NUL/CR/LF (pas d'injection), anti-flood (seau à jetons), file d'envoi bornée, limites de connexions globales / par IP / par minute, de salons, de cibles, timeouts d'enregistrement et de ping.
- **Audit** : événements sensibles (OPER, KILL, KLINE, REHASH, changements de mot de passe) journalisés (`log_file`).

## Fonctionnalités

| Domaine | Détail |
|---|---|
| Salons | `JOIN PART PRIVMSG NOTICE TOPIC NAMES LIST WHO WHOIS KICK INVITE KNOCK MODE` |
| Modes de salon | `b` (bans, masques `nick!user@hôte`, `$a` / `$a:compte`), `i` `k` `l` `m` `n` `R` (comptes seulement) `s` `t`, `o` `v` |
| Modes par défaut | `default_modes` (défaut `nt`) |
| IRCv3 | `sasl`, `server-time`, `echo-message`, `multi-prefix`, `away-notify`, `extended-join` |
| Historique | `history_lines` : rejoué à l'arrivée dans un salon (clients `server-time`), en mémoire |
| Infos | `LUSERS VERSION TIME INFO ADMIN MOTD USERHOST ISON AWAY` |
| Comptes | `PASSWD ancien nouveau` (change son mot de passe) |
| Opérateurs | `OPER`, `KILL`, `WALLOPS`, `KLINE` / `UNKLINE` (bans d'IP à jokers, en mémoire), `REHASH`, `DIE` |

## Utilisation

```bash
go build -o zinc .        # ou: make build
./zinc useradd alice      # mot de passe >= 10 caractères, lu sur stdin (sans écho)
./zinc serve              # TLS sur :6697
```

Commandes : `serve`, `check`, `useradd`, `userdel`, `users`, `hash`, `version` (toutes acceptent `-config fichier.json` sauf `hash` et `version`).

Un opérateur : `./zinc hash` produit le hash à mettre dans `opers`, puis `/OPER root motdepasse`.

`SIGHUP` (ou `/REHASH`) recharge comptes, opérateurs, empreintes, MOTD et historique sans redémarrer.

## Configuration

Voir [`zinc.example.json`](zinc.example.json) (les clés inconnues sont refusées). Tout est optionnel.

| Clé | Défaut | Rôle |
|---|---|---|
| `name` / `network` | `zinc.local` / `Zinc` | Nom du serveur / du réseau |
| `listen` | `:6697` | Adresse TLS |
| `cert_file` / `key_file` | `zinc.crt` / `zinc.key` | Certificat (auto-généré si absent) |
| `users_file` | `users.json` | Base des comptes |
| `motd_file`, `log_file` | — | MOTD ; journal (en plus de stderr) |
| `require_auth` | `true` | Refuse les clients non authentifiés |
| `tls13_only` | `false` | Refuse TLS 1.2 |
| `cloak_secret` | aléatoire | Secret de masquage d'IP (fixez-le pour garder les mêmes hôtes après redémarrage) |
| `max_clients`, `max_per_ip`, `connect_rate` | 1000, 5, 20/min | Limites de connexion |
| `max_channels` | 2000 | Salons simultanés |
| `ping_interval`, `reg_timeout` | 90 s, 30 s | Inactivité, délai d'enregistrement |
| `auth_max_fails` | 8 | Échecs avant blocage d'IP (10 min) |
| `default_modes` | `nt` | Modes des nouveaux salons (`i m n R s t`) |
| `history_lines` | 0 | Historique rejoué (max 200) |
| `opers` | — | `nom: hash` (`zinc hash`) |
| `certfp` | — | `empreinte SHA-256 du certificat client: compte` |
| `admin_name`, `admin_email` | — | Réponse à `ADMIN` |

## Déploiement

- **Docker** : `docker build -t zinc .` puis monter un volume `/data` contenant `zinc.json`.
- **systemd** : [`deploy/zinc.service`](deploy/zinc.service) (sandbox renforcé, `systemctl reload` = SIGHUP).
- **CI** : `.github/workflows/ci.yml` (vet + tests avec `-race`).

## Limites

Un seul serveur (pas de liaison S2S), pas de services (NickServ/ChanServ), K-lines et historique en mémoire uniquement.

Tests : `go test -race ./...`
