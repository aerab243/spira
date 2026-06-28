# 🌀 Spira

> **Outil d'analyse de vulnérabilités pour systèmes Linux**
> Multi-distro · CLI-first · Open-source · 100 % Rust

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](Cargo.toml)

Spira est un outil en ligne de commande qui détecte la distribution Linux sur laquelle il tourne, énumère les paquets installés, croise leurs versions avec la base de vulnérabilités NVD, audite la configuration système (SSH, firewall, sudoers) et produit un rapport de risque actionnable en plusieurs formats.

---

## 📑 Sommaire

- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Démarrage rapide](#-démarrage-rapide)
- [Référence des commandes](#-référence-des-commandes)
  - [`spira detect`](#spira-detect)
  - [`spira packages`](#spira-packages)
  - [`spira scan`](#spira-scan)
  - [`spira audit`](#spira-audit)
  - [`spira vulns`](#spira-vulns)
  - [`spira update`](#spira-update)
- [Options globales](#-options-globales)
- [Formats de sortie](#-formats-de-sortie)
- [Cache CVE local](#-cache-cve-local)
- [Distributions & gestionnaires supportés](#-distributions--gestionnaires-supportés)
- [Architecture du projet](#-architecture-du-projet)
- [Stack technique](#-stack-technique)
- [Développement](#-développement)
- [Roadmap](#-roadmap)
- [Crédits & licence](#-crédits--licence)

---

## ✨ Fonctionnalités

- 🔍 **Détection automatique** de la distribution, du noyau et du gestionnaire de paquets via `/etc/os-release` et `/proc/version`.
- 📦 **Énumération des paquets** installés pour les principales familles Linux : `dpkg` (Debian/Ubuntu), `rpm` (Fedora/RHEL/openSUSE), `pacman` (Arch/Manjaro), `apk` (Alpine).
- 🛡️ **Cross-référencement CVE ↔ paquets** grâce à un cache local SQLite alimenté par les flux NVD (CVE récents + modifiés).
- 🐧 **Scan du noyau Linux** pour identifier les vulnérabilités connues de la version active.
- 🌐 **Détection des services et ports ouverts** (`systemctl`, `ss`) avec heuristiques CVE sur les services exposés.
- 🔧 **Audit de configuration** :
  - **SSH** : `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`, `PermitEmptyPasswords`, ciphers/MAC/KEX recommandés.
  - **Firewall** : détection `iptables`, `nftables`, `firewalld`, `ufw` + scoring d'activité.
  - **sudoers** : `NOPASSWD`, `!authenticate`, groupes `wheel`/`sudo`, `secure_path`.
- 📊 **Rapports multi-formats** : terminal coloré, JSON (CI/CD), HTML (documentation), Markdown.
- 🌑 **Mode hors-ligne complet** grâce au cache SQLite local (`--offline`).
- 🎯 **Filtrage par sévérité** et limitation de sortie (`--max-cve`).

---

## 📦 Installation

### Prérequis

- **Rust** ≥ 1.75 (édition 2021)
- **OpenSSL** (ou `rustls` via les features par défaut — `rustls-tls` est inclus par défaut)
- Un système Linux supporté (voir [distributions supportées](#-distributions--gestionnaires-supportés))
- Permissions lecture sur `/etc`, `/proc`, et les sorties des gestionnaires de paquets
- Pour `spira scan` : accès à `systemctl` et `ss`

### Depuis les sources

```bash
git clone https://github.com/aerab243/spira.git
cd spira
cargo build --release
sudo cp target/release/spira /usr/local/bin/
```

### Via `cargo install`

```bash
cargo install --git https://github.com/aerab/spira
```

### Vérification

```bash
spira --version
```

---

## 🚀 Démarrage rapide

```bash
# 1. Détecter l'environnement (distro + noyau + gestionnaire)
spira detect

# 2. Mettre à jour le cache CVE depuis NVD (requiert Internet)
spira update

# 3. Scanner l'ensemble du système (paquets + noyau + services + ports)
spira scan

# 4. Auditer la configuration (SSH, firewall, sudoers)
spira audit

# 5. Chercher les CVE d'un paquet précis
spira vulns openssl

# 6. Export CI/CD en JSON
spira scan --format json > scan-report.json
```

---

## 📖 Référence des commandes

### `spira detect`

Détecte la distribution, le noyau et le gestionnaire de paquets.

```bash
spira detect [--kernel] [--packages] [--json]
```

| Option       | Description                                       |
| ------------ | ------------------------------------------------- |
| `--kernel`   | Affiche les informations détaillées sur le noyau. |
| `--packages` | Affiche les informations sur le gestionnaire.     |
| `--json`     | Sortie JSON raccourcie (option globale).          |

**Exemple :**

```
$ spira detect
Distro: Ubuntu 22.04.3 LTS (ubuntu)
Version: 22.04
Codename: jammy
Kernel: 6.5.0-15-generic [x86_64]
Package Manager: Dpkg
```

---

### `spira packages`

Liste tous les paquets installés via le gestionnaire détecté.

```bash
spira packages [--json]
```

Affiche, pour chaque paquet, son nom, sa version et sa source (le gestionnaire qui l'a installé).

---

### `spira scan`

Lance un **scan complet** : paquets + noyau + services + ports ouverts, puis croise avec le cache CVE local.

```bash
spira scan [OPTIONS]
```

| Option                  | Défaut       | Description                                                |
| ----------------------- | ------------ | ---------------------------------------------------------- |
| `--kernel`              | `true`       | Inclure le scan des vulnérabilités du noyau Linux.         |
| `--services`            | `true`       | Inclure la détection des services et l'analyse des ports.  |
| `-f`, `--format <FMT>`  | `terminal`   | Format : `terminal`, `json`, `html`, `markdown`.           |
| `--max-cve <N>`         | `0`          | Limite l'affichage aux N CVE les plus critiques (0 = tout). |

**Exemple :**

```bash
spira scan --format json --max-cve 20 > top20.json
```

---

### `spira audit`

Effectue un **audit de configuration** complet : SSH, firewall et sudoers.

```bash
spira audit [-f <FMT>]
```

Produit un score de sécurité pour chaque composant audité.

| Composant   | Vérifications principales                                                                  |
| ----------- | ------------------------------------------------------------------------------------------ |
| SSH         | Root login, authent par mot de passe, ciphers/MAC/KEX, empty passwords.                    |
| Firewall    | Présence et activité d'iptables/nftables/firewalld/ufw, règles par défaut.                 |
| sudoers     | `NOPASSWD`, `!authenticate`, appartenance `wheel`/`sudo`, `secure_path`.                   |

**Exemple :**

```bash
spira audit --format html > audit-$(hostname).html
```

---

### `spira vulns`

Cherche les CVE connues pour un paquet donné dans le cache local.

```bash
spira vulns <NAME>
```

Trie les résultats par score CVSS décroissant.

```bash
$ spira vulns openssl
3 vulnérabilité(s) pour 'openssl':
  CVE: CVE-2023-0464
    Score: 7.5
    Sévérité: HIGH
    CPE: cpe:2.3:a:openssl:openssl:1.1.1:-:*:*:*:*:*:*
    Versions affectées: ...
    Description: ...
```

---

### `spira update`

Télécharge les flux CVE récents depuis NVD et alimente le cache SQLite local.

```bash
spira update
```

- **Source 1** : `recent_cves.json.gz` — CVE des **8 derniers jours**.
- **Source 2** : `modified_cves.json.gz` — CVE **modifiés récemment** (sans limite d'âge).

> 💡 Sans connexion Internet, exécutez `spira update` au moins une fois, puis utilisez `--offline` pour les scans suivants.

---

## ⚙️ Options globales

| Option               | Description                                                              |
| -------------------- | ------------------------------------------------------------------------ |
| `-o`, `--output`     | Chemin du fichier de sortie (par défaut : stdout).                       |
| `--offline`          | Ne contacte aucun flux distant — s'appuie uniquement sur le cache local. |
| `-j`, `--json`       | Sortie JSON raccourcie (équivalent à `--format json` pour `detect`/`packages`). |
| `-V`, `--version`    | Affiche la version du programme.                                         |
| `-h`, `--help`       | Affiche l'aide complète de `spira` ou d'une sous-commande.               |

---

## 📊 Formats de sortie

Spira supporte **quatre formats de rapport**, sélectionnables via `--format` (`-f`) :

| Format      | Usage recommandé                                  | Couleurs | Notes                              |
| ----------- | ------------------------------------------------- | -------- | ---------------------------------- |
| `terminal`  | Lecture humaine interactive (défaut).             | ✅        | Sévérités colorées + tableaux.     |
| `json`      | Intégration CI/CD, ingestion SIEM, pipelines.     | ❌        | Schéma structuré stable.           |
| `html`      | Documentation partageable, audits visuels.        | ❌        | Template autonome, imprimable.     |
| `markdown`  | Wikis, tickets, intégrations GitHub/GitLab.       | ❌        | Compatible avec les viewers MD.    |

### Exemples

```bash
# Rapport terminal lisible
spira scan

# Export JSON pour pipeline
spira scan --format json --output scan.json

# Rapport HTML pour l'équipe sécurité
spira audit --format html --output audit.html

# Markdown pour un ticket Jira/GitHub
spira vulns openssl --format markdown
```

---

## 🗄️ Cache CVE local

Le cache CVE est stocké dans un fichier SQLite local :

```
./spira_cache.db
```

### Schéma (résumé)

| Table       | Colonnes principales                                                       |
| ----------- | -------------------------------------------------------------------------- |
| `cves`      | `id`, `description`, `severity`, `cvss_score`, `published`, `modified`.    |
| `cpe`       | `product`, `vendor`, `version_start`, `version_end`, `cve_id`.             |
| `packages`  | `name`, `version`, `distro` (cache des paquets scannés).                   |

### Workflow recommandé

```bash
# 1. Mise à jour hebdomadaire (ou quotidienne en CI)
spira update

# 2. Scan quotidien en local, sans réseau
spira scan --offline

# 3. Audit mensuel de conformité
spira audit --format html --output audit-$(date +%F).html
```

### Emplacement personnalisé

Par défaut, le cache est `./spira_cache.db`. Pour utiliser un autre chemin, modifiez la constante `DEFAULT_CACHE_PATH` dans `src/main.rs` ou déplacez le fichier avant l'exécution.

---

## 🐧 Distributions & gestionnaires supportés

| Famille    | Distributions                                         | Gestionnaire       |
| ---------- | ----------------------------------------------------- | ------------------ |
| Debian     | Debian, Ubuntu, Linux Mint, Pop!_OS, Elementary       | `dpkg`             |
| Red Hat    | Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux         | `rpm`              |
| SUSE       | openSUSE Leap, openSUSE Tumbleweed, SLES              | `rpm`              |
| Arch       | Arch Linux, Manjaro, EndeavourOS                      | `pacman`           |
| Alpine     | Alpine Linux                                          | `apk`              |

> La détection repose sur la présence du binaire du gestionnaire (`which dpkg`, etc.). Les dérivés transparents (Devuan, Kali, etc.) sont reconnus automatiquement.

---

## 🏗️ Architecture du projet

```
spira/
├── Cargo.toml                  # Manifeste Rust + dépendances
├── PLAN.md                     # Roadmap détaillée (10 phases)
├── README.md                   # Ce fichier
├── src/
│   ├── main.rs                 # Point d'entrée CLI
│   ├── cli.rs                  # Définitions clap (sous-commandes, options)
│   ├── lib.rs                  # Re-exports pour tests d'intégration
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── distro.rs           # Lecture /etc/os-release
│   │   ├── kernel.rs           # Version du noyau + CVEs noyau
│   │   ├── packages.rs         # Abstraction PackageManager
│   │   ├── package.rs          # Struct Package
│   │   ├── services.rs         # Services systemd + ports ouverts
│   │   └── network.rs          # Heuristiques CVE sur les ports
│   ├── cve/
│   │   ├── mod.rs
│   │   ├── nvd.rs              # Client NVD API + parsing flux gzippés
│   │   ├── cache.rs            # SQLite (schéma, upserts, requêtes)
│   │   └── matcher.rs          # Matching version ↔ CPE
│   ├── audit/
│   │   ├── mod.rs
│   │   ├── ssh.rs              # Audit /etc/ssh/sshd_config
│   │   ├── firewall.rs         # Audit iptables/nftables/firewalld/ufw
│   │   └── sudoers.rs          # Audit /etc/sudoers + /etc/sudoers.d/*
│   ├── reporter/
│   │   ├── mod.rs              # Enum ReportFormat
│   │   ├── terminal.rs         # Sortie colorée + tableaux
│   │   ├── json.rs             # Sérialisation serde_json
│   │   ├── html.rs             # Template HTML autonome
│   │   └── markdown.rs         # Tables markdown
│   └── utils/
│       ├── mod.rs
│       └── (helpers)           # truncate, version compare, etc.
└── tests/                      # Tests d'intégration (cargo test)
```

### Modules principaux

| Module     | Responsabilité                                                                 |
| ---------- | ------------------------------------------------------------------------------ |
| `scanner`  | Collecte d'informations système (distro, paquets, noyau, services, ports).     |
| `cve`      | Récupération, stockage et matching des vulnérabilités (CVE + CPE).             |
| `audit`    | Analyse statique des fichiers de configuration (SSH, firewall, sudoers).       |
| `reporter` | Génération des rapports multi-formats à partir des structures internes.         |
| `utils`    | Helpers transverses (troncature, comparaison de versions semver, etc.).         |

---

## 🛠️ Stack technique

| Couche         | Technologie                                            |
| -------------- | ------------------------------------------------------ |
| Langage        | Rust (édition 2021) — stabilité, perf, safety mémoire |
| CLI            | `clap` v4 (derive)                                     |
| Sérialisation  | `serde` + `serde_json`                                 |
| Cache / DB     | `rusqlite` (SQLite, bundle statique)                   |
| HTTP client    | `reqwest` (blocking, `rustls-tls`)                     |
| Compression    | `flate2` (flux NVD gzippés)                            |
| Versions       | `semver`                                               |
| Dates          | `chrono` (avec feature `serde`)                        |
| Erreurs        | `thiserror`                                            |

### Choix d'architecture

- **Static SQLite** (`features = ["bundled"]`) : aucune dépendance système à `libsqlite3`.
- **Rustls** plutôt qu'OpenSSL : déploiement simplifié, surface d'attaque réduite.
- **Cache local obligatoire** : permet un mode `--offline` complet après la première mise à jour.
- **Séparation claire** scan / audit / cve / reporter : chaque module est testable indépendamment.

---

## 👨‍💻 Développement

### Build

```bash
cargo build              # debug
cargo build --release    # release optimisée
```

### Tests

```bash
cargo test                          # tests unitaires + intégration
cargo test --test distro_tests      # test d'intégration ciblé
cargo test -- --nocapture           # voir stdout des tests
```

### Lints

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo fmt
```

### Lancer un scan de développement

```bash
# Avec logs verbeux
RUST_LOG=debug cargo run -- scan --max-cve 5

# Sur votre propre machine
cargo run -- audit
cargo run -- vulns bash
```

### Tests en isolation

Le projet utilise une base SQLite embarquée (`bundled`). Pour tester sans toucher au cache utilisateur :

```bash
SPIRA_CACHE=$(mktemp).db cargo test
```

---

## 🗺️ Roadmap

Le projet suit un plan en **6 phases** (voir [`PLAN.md`](PLAN.md) pour le détail complet).

| Phase | Nom                       | Statut      |
| ----- | ------------------------- | ----------- |
| 0     | Fondations (détection)    | ✅ Livrée    |
| 1     | Énumération paquets       | ✅ Livrée    |
| 2     | Base CVE & cache SQLite   | ✅ Livrée    |
| 3     | Scanner noyau & services  | ✅ Livrée    |
| 4     | Audit configuration       | ✅ Livrée    |
| 5     | Reporting multi-format    | ✅ Livrée    |
| 6     | Polissage & v1.0          | 🚧 En cours |

### Post-v1.0

| Fonctionnalité                                          | Priorité |
| ------------------------------------------------------- | -------- |
| Intégration exploits (Exploit-DB, Metasploit)           | 🔴 Haute |
| Scan compliance (CIS Benchmarks)                        | 🔴 Haute |
| Scan réseau (nmap-style, CVE sur services distants)     | 🟡 Moyenne |
| Scan conteneurs (Docker/Podman)                         | 🟡 Moyenne |
| Système de plugins communautaires                       | 🟢 Basse  |
| Interface Tauri (GUI web)                               | 🟢 Basse  |
| Intégration SIEM / JSON-LD                              | 🟢 Basse  |

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour proposer un changement :

1. **Fork** le dépôt et crée une branche (`git checkout -b feature/ma-fonctionnalite`).
2. **Commit** tes changements (`git commit -m "feat: ajoute le scan conteneurs"`).
3. **Push** la branche (`git push origin feature/ma-fonctionnalite`).
4. Ouvre une **Pull Request** avec une description claire.

### Conventions

- Respecter `rustfmt` et `clippy` (CI bloquante).
- Ajouter des tests unitaires pour toute nouvelle logique métier.
- Documenter les nouvelles options CLI dans `cli.rs` (le `--help` en dépend).
- Mettre à jour `PLAN.md` si tu coches une étape de la roadmap.

### Idées de contributions

- Ajouter un nouveau backend `PackageManager` (Nix, Flatpak, Snap…).
- Implémenter un nouveau module d'audit (ex. `audit/nginx.rs`, `audit/mysql.rs`).
- Étendre le matching CPE (gestion des ranges préfixés, vendor normalization).
- Internationaliser les rapports (`--lang fr|en`).

---

## 🔒 Considérations de sécurité

Spira est un outil **d'audit en lecture seule** :

- ❌ Il **ne modifie aucun fichier de configuration**.
- ❌ Il **n'installe, ne supprime, ne met à jour aucun paquet**.
- ✅ Il lit `/etc`, `/proc`, les sorties des gestionnaires de paquets et les fichiers `systemctl`/`ss`.
- ⚠️ Certains audits (`sudoers`, `/etc/ssh/sshd_config`) peuvent nécessiter des privilèges élevés pour accéder à toutes les informations.

### Permissions recommandées

```bash
# Lecture seule, sans sudo
spira detect
spira packages
spira scan --offline
spira audit

# Privilèges élevés pour audit exhaustif
sudo spira audit
```

---

## 📚 Crédits & licence

### Sources de données

- **NVD** (National Vulnerability Database) — [nvd.nist.gov](https://nvd.nist.gov/) — base CVE et CPE.
- **os-release spec** — [freedesktop.org](https://www.freedesktop.org/software/systemd/man/os-release.html).

### Inspiration

- [`lynis`](https://github.com/CISOfy/lynis) — audit de sécurité système.
- [`vulners`](https://vulners.com/) — agrégation de CVE multi-sources.
- [`arch-audit`](https://github.com/ilpianista/arch-audit) — audit CVE spécifique Arch Linux.

### Licence

Ce projet est distribué sous licence **Apache-2.0**. Voir [`LICENSE`](LICENSE) pour le texte complet.

> ℹ️ Apache-2.0 inclut une **cession explicite de licence de brevets** (patent grant), ce qui protège les contributeurs et utilisateurs en cas de litige sur des implémentations de standards (CPE, flux NVD, etc.).

---

## 📬 Contact & support

- 🐛 **Bugs / demandes** : [GitHub Issues](https://github.com/aerab/spira/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/aerab/spira/discussions)
- 📖 **Documentation complète** : [`PLAN.md`](PLAN.md) (roadmap détaillée)

---

<p align="center">
  <sub>Construit avec ❤️ et 🦀 en Rust. Contributions bienvenues !</sub>
</p>
