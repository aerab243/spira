# Spira — Plan & Roadmap

## Vision

Outil d'analyse de vulnérabilités pour systèmes Linux, multi-distro, CLI-first,
open-source, capable de scanner paquets, noyau, configuration et services pour
produire un rapport de risque actionnable.

---

## Objectifs (v1.0)

- Détecter automatiquement la distro et sa version
- Enumerer les paquets installés et cross-référencer avec la base CVE (NVD)
- Détecter les vulnérabilités du noyau Linux
- Auditer la configuration SSH, firewall (iptables/nftables/firewalld) et sudoers
- Générer un rapport structuré (terminal coloré + JSON)
- Fonctionner hors-ligne avec un cache local des CVEs

---

## Stack technique

| Couche         | Techno                                  |
| -------------- | --------------------------------------- |
| Langage        | Rust (stabilité, perf, sécurité mémoire) |
| CLI            | `clap` v4 + `crossterm` (couleurs)      |
| Cache / DB     | `rusqlite` (SQLite)                     |
| HTTP           | `reqwest`                               |
| CVE matching   | Logique custom + NVD API 2.0            |
| Build          | Cargo + clippy + rustfmt                |
| CI             | GitHub Actions (lint + tests)           |

---

## Phases du roadmap

### Phase 0 — Fondations (Semaine 1)

**Objectif :** Setup projet + détection distro fonctionnelle

- [ ] Initialiser projet Cargo avec workspace
- [ ] Configurer `clap` CLI (`--version`, `--output`, `--offline`, `--json`)
- [ ] Module `distro`: lire `/etc/os-release`, détecter distro + version + codename
- [ ] Module `detector`: détecter le gestionnaire de paquets (rpm/dpkg/pacman/apk)
- [ ] Module `kernel`: lire `/proc/version` et `uname -r`
- [ ] Tests unitaires sur la détection distro

**Livrable :** `spira --version` + `spira detect` affiche distro/kernel/package-manager

---

### Phase 1 — Énumération des paquets (Semaines 2-3)

**Objectif :** Lister tous les paquets installés

- [ ] Module `packages` — abstraction `PackageManager`
  - [ ] `RpmManager` (Fedora, RHEL, openSUSE)
  - [ ] `DpkgManager` (Debian, Ubuntu)
  - [ ] `PacmanManager` (Arch, Manjaro)
  - [ ] `ApkManager` (Alpine)
  - [ ] Exécution des commandes natives (`rpm -qa`, `dpkg -l`, etc.)
  - [ ] Parsing et normalisation des noms/versions
- [ ] Module `package` — struct `Package { name, version, source }`
- [ ] Tests avec mock de sortie de commandes

**Livrable :** `spira packages` liste tous les paquets installés

---

### Phase 2 — Base de données CVE & Cache (Semaines 4-5)

**Objectif :** Récupérer et stocker les CVEs localement

- [ ] Module `cve/cache.rs` — schéma SQLite
  - Table `cves` (id, description, severity, cvss_score, published, modified)
  - Table `cpe` (product, vendor, version_start, version_end, cve_id)
  - Table `packages` (name, version, distro) — cache des paquets scannés
- [ ] Module `cve/nvd.rs` — client API NVD 2.0
  - Fetch paginé des CVEs récentes
  - Parsing JSON avec `serde`
  - Rate limiting (respecter les limites NVD)
- [ ] Module `cve/match.rs` — matching paquet → CVE
  - Comparaison version avec CPE URI
  - Algorithme de range version (start <= installed < end)
- [ ] Commandes CLI `spira update` (mettre à jour le cache) et `--offline`

**Livrable :** `spira update` + `spira vulns --offline` affiche les paquets à risque

---

### Phase 3 — Scanner noyau & services (Semaine 6)

**Objectif :** Étendre au-delà des paquets

- [ ] Module `scanner/kernel.rs`
  - Détecter la version du noyau
  - Fetch CVEs spécifiques au noyau Linux (via CPE `cpe:2.3:o:linux:linux_kernel`)
  - Afficher les exploits disponibles (si intégré plus tard)
- [ ] Module `scanner/services.rs`
  - Détecter les services systemd actifs
  - Détecter les ports ouverts (`ss -tulpn` ou équivalent)
  - Identifier les services non sécurisés par défaut
- [ ] Module `scanner/network.rs`
  - Vérifier les ports ouverts et les associer à des CVEs connues

**Livrable :** `spira scan` effectue un scan complet (paquets + noyau + services)

---

### Phase 4 — Audit configuration (Semaine 7)

**Objectif :** Vérifier les failles de configuration

- [ ] Module `audit/ssh.rs`
  - Vérifier `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`
  - Vérifier les cipher/MAC et algo KEX recommandés
  - Score de faiblesse
- [ ] Module `audit/firewall.rs`
  - Détecter iptables / nftables / firewalld / ufw
  - Vérifier si actif et règles par défaut
  - Détecter ports ouverts non justifiés
- [ ] Module `audit/sudoers.rs`
  - Vérifier `NOPASSWD`, `!authenticate`, groupe `wheel`/`sudo`
  - Détecter les chemins PATH dangereux

**Livrable :** `spira audit` affiche les problèmes de configuration avec recommandations

---

### Phase 5 — Reporting (Semaine 8)

**Objectif :** Générer des rapports exploitables

- [ ] Reporter terminal (couleurs, barres de progression, tableaux)
  - Severity colorée (critique/élevée/moyenne/faible)
  - Score global du système
- [ ] Export JSON structuré pour intégration CI/CD
- [ ] Export HTML avec recommandations par CVE
- [ ] Export Markdown pour documentation

**Livrable :** `spira scan --format json` + `spira audit --format html`

---

### Phase 6 — Polissage & v1.0 (Semaines 9-10)

**Objectif :** Prêt pour release publique

- [ ] Optimisation des performances (parallélisation des requêtes)
- [ ] Amélioration du matching CPE (gestion des ranges, préfixes vendor/product)
- [ ] Documentation README complète
- [ ] Script d'installation (cargo install, AUR, COPR pour Fedora)
- [ ] CI/CD GitHub Actions
  - Lint (clippy + rustfmt)
  - Tests unitaires + tests d'intégration
  - Build multi-arch (x86_64, aarch64)
- [ ] Release binaire + package Fedora RPM
- [ ] Logo et branding

**Livrable :** v1.0.0 publiée sur GitHub + COPR Fedora

---

## Post-v1.0 (Futur)

| Feature                      | Priorité |
| ---------------------------- | -------- |
| Intégration exploits (Exploit-DB, Metasploit) | Haute   |
| Scan réseau (nmap-style, CVE sur services distants) | Moyenne |
| Plugin system (extensions communautaires) | Basse   |
| Interface Tauri (GUI web)    | Basse   |
| Intégration SIEM / JSON-LD  | Basse   |
| Scan conteneurs (Docker/Podman) | Moyenne |
| Scan compliance (CIS Benchmarks) | Haute  |

---

## Structure du projet

```
spira/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── PLAN.md                          # Ce fichier
├── src/
│   ├── main.rs                      # CLI entry point
│   ├── cli.rs                       # Définitions clap
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── distro.rs                # Détection distro + kernel
│   │   ├── packages.rs              # Gestionnaire de paquets
│   │   ├── kernel.rs                # Vulnérabilités noyau
│   │   ├── services.rs              # Services systemd
│   │   └── network.rs               # Ports ouverts
│   ├── cve/
│   │   ├── mod.rs
│   │   ├── nvd.rs                   # Client NVD API
│   │   ├── cache.rs                 # SQLite cache
│   │   └── matcher.rs               # Matching CPE → paquet
│   ├── audit/
│   │   ├── mod.rs
│   │   ├── ssh.rs                   # Audit SSH
│   │   ├── firewall.rs              # Audit firewall
│   │   └── sudoers.rs               # Audit sudoers
│   ├── reporter/
│   │   ├── mod.rs
│   │   ├── terminal.rs              # Sortie terminal colorée
│   │   ├── json.rs                  # Export JSON
│   │   └── html.rs                  # Export HTML
│   └── utils/
│       ├── mod.rs
│       └── version.rs               # Comparaison de versions semver
├── tests/
│   ├── distro_tests.rs
│   ├── packages_tests.rs
│   └── cve_matcher_tests.rs
└── assets/
    └── report_template.html         # Template pour export HTML
```

---

## Commands CLI cibles

```
spira detect                    # Affiche distro, kernel, package manager
spira packages                  # Liste les paquets installés
spira update                    # Met à jour le cache NVD local
spira scan                      # Scan complet (paquets + noyau + services)
spira scan --format json        # Export JSON
spira audit                     # Audit configuration (SSH, firewall, sudoers)
spira vulns <package-name>      # Cherche CVEs pour un paquet spécifique
spira --version                 # Version du programme
spira --offline                 # Force le mode hors-ligne
spira --severity critical       # Filtrer par sévérité minimale
```
