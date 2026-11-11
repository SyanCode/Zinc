# Zinc

IRC, mais on a pensé à la sécurité cette fois.

Serveur IRC en Go, **sans aucune dépendance** (bibliothèque standard uniquement).

## Sécurité

- **TLS obligatoire** : il n'y a pas de port en clair. TLS 1.2 minimum (suites ECDHE + AEAD), TLS 1.3 supporté. Certificat auto-signé généré au premier lancement (l'empreinte SHA-256 est affichée), ou fournissez le vôtre.
- **Authentification par comptes** (`require_auth: true` par défaut) via **SASL PLAIN** (sûr car sous TLS) ou `PASS compte:motdepasse`.
- **Mots de passe** hachés en PBKDF2-HMAC-SHA256 (600 000 itérations, sel aléatoire), comparaison en temps constant, fichier des comptes en `0600`, calculs bornés (anti-DoS CPU) et vérification factice pour les comptes inconnus (pas d'énumération par le temps).
- **Anti brute-force** : 3 échecs SASL = déconnexion ; trop d'échecs depuis une IP = blocage 10 min.
- **IP masquées** : les autres utilisateurs ne voient qu'un hôte HMAC (`zn-xxxxxxxxxxxx.cloak`). Ident forcé en `~user` assaini.
- **Pseudos protégés** : un pseudo égal à un compte n'est utilisable que par ce compte authentifié.
- **Durcissement protocole** : lignes limitées à 512 octets, caractères de contrôle (NUL/CR/LF) filtrés (pas d'injection de commandes), anti-flood (seau à jetons), file d'envoi bornée, limites de connexions globales/par IP, de salons, de cibles par message, timeouts d'enregistrement et de ping.
- **Salons** : créateur opérateur, `+nt` par défaut, modes `i m n s t k l o v`, clés comparées en temps constant, salons secrets invisibles.

## Utilisation

```bash
go build -o zinc .
./zinc useradd alice          # crée le compte (mot de passe >= 10 caractères, lu sur stdin)
./zinc serve                  # écoute en TLS sur :6697
```

`SIGHUP` recharge `users.json` sans redémarrer. Configuration optionnelle : `./zinc serve -config zinc.json`

```json
{
  "name": "irc.exemple.org",
  "listen": ":6697",
  "cert_file": "fullchain.pem",
  "key_file": "privkey.pem",
  "require_auth": true,
  "max_per_ip": 5
}
```

Les clés inconnues dans la config sont refusées. Tests : `go test -race ./...`
