# Spira — Roadmap étendue (Phase 7+)

> Ce document complète [`PLAN.md`](PLAN.md) en détaillant les phases **post-v1.0**.
> Il reprend les 14 améliorations proposées et les structure en **9 phases
> cohérentes** (7 à 15), avec dépendances, estimations et livrables.
>
> Légende priorité : 🔴 Haute · 🟡 Moyenne · 🟢 Basse

---

## 🎯 Vue d'ensemble

| Phase | Nom                              | Statut    | Semaine | Dépend de |
| ----- | -------------------------------- | --------- | ------- | --------- |
| 7     | Observabilité & UX CLI           | 🚧 À faire | S11     | v1.0      |
| 8     | Performance & cache SQLite       | 🚧 À faire | S12-13  | 7         |
| 9     | Configuration & profils          | 🚧 À faire | S14     | 7         |
| 10    | Sources CVE distro-spécifiques   | 🚧 À faire | S15-17  | 8         |
| 11    | EPSS & exploits                  | 🚧 À faire | S18-19  | 8         |
| 12    | Reporting SARIF                  | 🚧 À faire | S20     | 9         |
| 13    | Drift detection                  | 🚧 À faire | S21-22  | 8, 12     |
| 14    | Compliance CIS Benchmarks        | 🚧 À faire | S23-26  | 9         |
| 15    | Écosystème & distribution        | 🚧 À faire | S27-28  | 7, 12     |

**Effort total estimé :** ~18 semaines de travail (≈ 4 mois et demi).

---

## Phase 7 — Observabilité & UX CLI *(Semaine 11)*

**Objectif :** Remplacer les `eprintln!` par du logging structuré, améliorer
l'expérience CLI avec auto-complétion et barres de progression. Quick wins qui
bénéficient à toutes les phases suivantes.

### Tâches

- [ ] **Migration `tracing`**
  - [ ] Ajouter `tracing` + `tracing-subscriber` au `Cargo.toml`
  - [ ] Remplacer tous les `eprintln!` par `tracing::{info, warn, error, debug}`
  - [ ] Subscribers `pretty` (TTY) et `json` (CI/CD) via variable `SPIRA_LOG_FORMAT`
  - [ ] Niveaux configurables via `RUST_LOG=spira=debug`
  - [ ] Spans instrumentés pour chaque sous-commande (`scan`, `audit`, `update`)
- [ ] **Shell completions**
  - [ ] Utiliser `clap_complete` (feature `derive` côté `cli`)
  - [ ] Sous-commande cachée `spira completions <bash|zsh|fish|powershell>`
  - [ ] Documentation d'install dans `README.md`
- [ ] **Progress bars**
  - [ ] Ajouter `indicatif` au `Cargo.toml`
  - [ ] Barre pendant `spira update` (fetch NVD paginé)
  - [ ] Spinner pendant scans partiels (`scanning SSH config…`, `scanning firewall…`)
  - [ ] ETA estimé pour les phases longues
- [ ] **Manpage**
  - [ ] Ajouter `clap_mangen`
  - [ ] Générer `assets/man/spira.1` au build (script `build.rs` ou `make man`)
  - [ ] Installer via `make install-man`
- [ ] **Tests**
  - [ ] Tester que `--log-level` parse bien les niveaux
  - [ ] Tester que `RUST_LOG` est respecté
  - [ ] Snapshot test des completions générées

### Livrables

- `spira scan --log-format json` produit des logs structurés exploitables en CI
- `spira completions bash > /etc/bash_completion.d/spira` fonctionne
- `man spira` affiche la documentation complète
- Barres de progression sur toutes les opérations > 2 s

---

## Phase 8 — Performance & cache SQLite *(Semaines 12-13)*

**Objectif :** Passer à un runtime async pour paralléliser I/O et audits ;
durcir le cache SQLite pour absorber la montée en charge des phases 10+.

### Tâches

- [ ] **Migration async (Rust + Tokio)**
  - [ ] Activer feature `tokio` sur `reqwest`
  - [ ] Wrapper `block_on` sur le main existant, ou migration complète `async fn main`
  - [ ] Paralléliser les audits (`tokio::join!` sur SSH + firewall + sudoers)
  - [ ] Paralléliser les requêtes NVD avec `futures::stream::FuturesUnordered`
  - [ ] Rate limiter partagé (`tokio::sync::Semaphore`) pour respecter quotas NVD
- [ ] **SQLite hardening**
  - [ ] Activer **WAL mode** (`PRAGMA journal_mode = WAL`)
  - [ ] Activer `synchronous = NORMAL` (durabilité + perf)
  - [ ] Augmenter `cache_size` à `-64000` (64 Mo)
  - [ ] `PRAGMA mmap_size = 268435456` (256 Mo mmap)
  - [ ] Augmenter `temp_store = MEMORY`
- [ ] **Index & schéma**
  - [ ] Index composites : `(vendor, product, version_start, version_end)`
  - [ ] Index sur `cves.published` (pour requêtes "récents")
  - [ ] Index sur `cves.severity`
  - [ ] Table `schema_version` pour migrations versionnées
  - [ ] Écrire migrations v1→v2→v3 (alter tables, création index)
- [ ] **Benchmarks**
  - [ ] Ajouter `criterion` aux dev-dependencies
  - [ ] Bench `matches_version` (hotspot identifié, fan-in = 5)
  - [ ] Bench `CveCache::search_cves_by_cpe` (cas typique scan)
  - [ ] Bench comparaison sync vs async sur NVD fetch (100 CVEs)
  - [ ] Seuils CI : fail si regression > 10 %
- [ ] **Tests**
  - [ ] Tests d'accès concurrent SQLite (10 readers + 1 writer)
  - [ ] Test de migration ascendante (v1 → v2 → v3 → latest)
  - [ ] Test de corruption recovery (PRAGMA integrity_check)

### Livrables

- `spira scan` sur machine à 1000 paquets < 30 s (vs ~2 min sync)
- Cache SQLite supporte 100 000+ CVEs sans dégradation
- Benchmarks reproductibles via `cargo bench`

---

## Phase 9 — Configuration & profils *(Semaine 14)*

**Objectif :** Permettre aux utilisateurs avancés de personnaliser Spira sans
recompiler, et introduire des profils d'audit adaptés au contexte.

### Tâches

- [ ] **Chargement de configuration**
  - [ ] Ajouter `serde` + `toml` au `Cargo.toml`
  - [ ] Chemins de recherche : `$SPIRA_CONFIG`, `~/.config/spira/config.toml`, `/etc/spira/config.toml`
  - [ ] Struct `Config { nvd_api_key, severity_threshold, exclude_packages, … }`
  - [ ] Validation au démarrage, erreur claire si TOML invalide
- [ ] **Sous-commande `spira config`**
  - [ ] `spira config show` — affiche config effective
  - [ ] `spira config set <key> <value>` — modifie via API
  - [ ] `spira config path` — affiche le fichier utilisé
  - [ ] `spira config init` — écrit un fichier par défaut
- [ ] **Exclusions de paquets**
  - [ ] Section `[exclude]` avec patterns glob (`docker-*`)
  - [ ] Section `[exclude.cves]` avec liste de CVE IDs
  - [ ] Champ `reason` obligatoire pour audit
  - [ ] Marquage `excluded: true` dans le rapport (transparence)
- [ ] **Profils d'audit**
  - [ ] Profils builtin : `strict` (prod), `balanced` (défaut), `permissive` (dev)
  - [ ] Profils custom dans `[profiles.<name>]` du TOML
  - [ ] Override par commande : `spira audit --profile strict`
  - [ ] Chaque règle d'audit indique ses niveaux par profil
- [ ] **Clé API NVD**
  - [ ] Lecture depuis env `SPIRA_NVD_API_KEY` ou config
  - [ ] Rate limit auto-ajusté (5 req/30s sans clé, 50 req/30s avec)
  - [ ] Message informatif au démarrage si clé manquante
- [ ] **Tests**
  - [ ] Tests de chargement config (override env vs fichier)
  - [ ] Tests d'exclusion par glob
  - [ ] Tests de sélection de profil

### Livrables

- `~/.config/spira/config.toml` permet de configurer sans recompiler
- `spira audit --profile strict` adapte les seuils
- Exclusion de faux positifs documentée dans le rapport

---

## Phase 10 — Sources CVE distro-spécifiques *(Semaines 15-17)*

**Objectif :** Compléter la NVD avec les flux officiels des distributions pour
éliminer les faux négatifs (paquets vulnérables mais non remontés par NVD).

### Tâches

- [ ] **Architecture plugin**
  - [ ] Trait `DistroFeed` dans nouveau module `cve/feeds/`
  - [ ] Méthodes : `name()`, `fetch()`, `parse()`, `match_package()`
  - [ ] Auto-détection du feed actif selon `distro.id` (debian → DSA, etc.)
  - [ ] Registre centralisé `FeedRegistry` pour orchestration
- [ ] **Feed Debian Security Advisory (DSA)**
  - [ ] Source : `https://security-tracker.debian.org/tracker/data/json`
  - [ ] Endpoint JSON : ~50 Mo, refresh quotidien
  - [ ] Parser : `Package { name, fixed_version, vulnerable_versions, debian_release }`
  - [ ] Mapping `debian_release` ↔ `dpkg` packages
- [ ] **Feed Ubuntu Security Notice (USN)**
  - [ ] Source : `https://ubuntu.com/security/notices` (atom feed + API JSON)
  - [ ] Endpoint : `https://api.security.ubuntu.com/security/notices.json`
  - [ ] Matching via `debian_mapping` (Ubuntu hérite de Debian)
- [ ] **Feed Red Hat Security Advisory (RHSA)**
  - [ ] Source : `https://access.redhat.com/security/data/csaf/cve/`
  - [ ] Format CSAF 2.0 (JSON structuré)
  - [ ] Inclusion Fedora (mêmes flux que RHEL via `redhat-oval`)
- [ ] **Feed Arch Linux Vuln Tracker (AVL)**
  - [ ] Source : `https://security.archlinux.org/all.json`
  - [ ] Endpoint JSON compact, ~5 Mo
  - [ ] Parsing direct (modèle déjà CVE-aware)
- [ ] **Modèle de données unifié**
  - [ ] Extension table `cves` : colonnes `distro_specific_id`, `source_feed`
  - [ ] Contrainte `UNIQUE(cve_id, source_feed, package_name)`
  - [ ] Matching prioritaire : si feed distro existe pour le paquet, il prime sur NVD
- [ ] **CLI**
  - [ ] `spira update --feed all|nvd|debian|ubuntu|redhat|arch`
  - [ ] `spira update --since YYYY-MM-DD` (incremental)
  - [ ] Statut par feed dans la sortie terminal
- [ ] **Tests**
  - [ ] Snapshot parser DSA sur 5 advisories réelles
  - [ ] Snapshot parser USN sur 5 notices
  - [ ] Test d'intégration : feed Arch + container Arch dans CI
  - [ ] Test de matching : paquet backporté Fedora détecté via RHSA

### Livrables

- `spira update` pull les 4 flux (NVD + Debian + Ubuntu + RHEL + Arch)
- `spira vulns openssl` sur Debian remonte **plus** de CVEs qu'en mode NVD seul
- Documentation : tableau des sources par distro

---

## Phase 11 — EPSS & enrichissement CVE *(Semaines 18-19)*

**Objectif :** Prioriser les CVEs par **probabilité d'exploitation réelle** au
lieu du seul CVSS théorique.

### Tâches

- [ ] **Client EPSS**
  - [ ] Source : `https://api.first.org/data/v1/epss` (FIRST.org, format CSV)
  - [ ] Endpoint bulk : `https://api.first.org/data/v1/epss?all` (~50 Mo gzip)
  - [ ] Mise à jour quotidienne
  - [ ] Nouveau module `cve/epss.rs`
- [ ] **Stockage**
  - [ ] Nouvelle table `epss(cve_id PRIMARY KEY, score REAL, percentile REAL, fetched_at)`
  - [ ] Index sur `score DESC` pour tri rapide
  - [ ] Téléchargement parallèle au NVD update
- [ ] **Scoring composite**
  - [ ] Nouveau champ `risk_score` = combinaison pondérée CVSS × EPSS
  - [ ] Pondération par défaut : `0.4 * cvss_normalized + 0.6 * epss_score`
  - [ ] Pondération configurable dans `config.toml`
  - [ ] Tri par `risk_score` décroissant par défaut dans les rapports
- [ ] **Intégration Exploit-DB**
  - [ ] Source : `https://www.exploit-db.com/` (CSV export)
  - [ ] Endpoint : `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
  - [ ] Matching par `cve_id` (pas toujours présent → fallback par EDB-ID)
  - [ ] Nouveau flag `has_public_exploit: bool` dans le rapport
- [ ] **Métasploit** *(optionnel)*
  - [ ] Module rapide : parser `modules/auxiliary/`, `modules/exploits/`
  - [ ] Si module présent → flag `metasploit_module: true`
  - [ ] Skip si trop lourd → post-MVP
- [ ] **Affichage**
  - [ ] Colonne supplémentaire "EPSS" dans rapport terminal
  - [ ] Indicateur visuel 🔥 pour CVEs avec exploit public
  - [ ] Tri par défaut : `risk_score` desc
- [ ] **Tests**
  - [ ] Snapshot parser EPSS CSV sur 10 lignes
  - [ ] Test calcul `risk_score` (multiplicateur configurable)
  - [ ] Test de tri (CVE haute EPSS / bas CVSS remonte avant bas EPSS / haut CVSS)

### Livrables

- Une CVE "Critical" CVSS=9.8 mais EPSS=0.02 ne masque plus une "High" CVSS=7.5 mais EPSS=0.85
- Rapport signale les exploits publics disponibles
- Tri par risque réel, pas par score théorique

---

## Phase 12 — Reporting SARIF *(Semaine 20)*

**Objectif :** Intégration native avec les plateformes de CI/CD (GitHub Code
Scanning, GitLab Code Quality, IDE).

### Tâches

- [ ] **Module `reporter/sarif.rs`**
  - [ ] Dépendance : `serde_json` (déjà présent), `sarif` crate ou struct custom
  - [ ] Implémenter `Reporter` pour `SarifReport`
  - [ ] Mapping sévérité CVSS → `level` SARIF (`error`, `warning`, `note`)
  - [ ] Inclure `tool.driver.version` depuis `CARGO_PKG_VERSION`
  - [ ] Inclure `rules` (déduplication des CVE IDs)
  - [ ] Inclure `results` (un par finding de paquet)
- [ ] **Locations & fixes**
  - [ ] `result.location.physicalLocation.artifactLocation.uri` = nom du paquet
  - [ ] `result.properties.package_name`, `package_version`, `cve_id`
  - [ ] `result.fixes[]` suggérant `apt upgrade <pkg>` / `dnf update <pkg>` (sans exécution)
- [ ] **CLI**
  - [ ] Flag `--format sarif`
  - [ ] Sortie stdout par défaut, `--output report.sarif` pour fichier
  - [ ] Exit code : 0 si clean, 1 si findings ≥ seuil de sévérité
- [ ] **Tests**
  - [ ] Snapshot SARIF output (validation JSON Schema)
  - [ ] Test que GitHub Code Scanning accepte l'output (`sarif-tools validate`)
- [ ] **Documentation**
  - [ ] Section README "Intégration GitHub Actions"
  - [ ] Exemple de workflow upload-sarif
  - [ ] Section "Intégration GitLab"

### Livrables

- `spira scan --format sarif > results.sarif` valide contre le schéma SARIF 2.1.0
- Upload direct vers GitHub Code Scanning fonctionne
- Sortie exploitable par VS Code SARIF Viewer

---

## Phase 13 — Drift detection *(Semaines 21-22)*

**Objectif :** Permettre de comparer deux scans dans le temps pour détecter
l'apparition/disparition de vulnérabilités. Killer feature pour usage récurrent.

### Tâches

- [ ] **Modèle de comparaison**
  - [ ] Définir une **clé stable** par finding : `(package_name, cve_id, source_feed)`
  - [ ] Set operations : `new = current - baseline`, `resolved = baseline - current`, `unchanged = ∩`
  - [ ] Hash SHA256 d'un scan (snapshot reproductible)
- [ ] **Sous-commande `spira diff`**
  - [ ] `spira diff --baseline yesterday.json --now today.json`
  - [ ] Sections : "🆕 New CVEs (N)", "✅ Resolved CVEs (M)", "⚠️ Still present (K)"
  - [ ] Tri par sévérité décroissante dans chaque section
  - [ ] Exit code : 0 si aucun new critical/high, 1 sinon (CI gate)
- [ ] **Format de baseline**
  - [ ] Accepter JSON, SARIF, Markdown en input
  - [ ] Détection auto du format via magic bytes / extension
  - [ ] Conversion interne vers représentation canonique
- [ ] **Stockage local d'historique**
  - [ ] Option `--save-baseline` : stocke dans `~/.local/share/spira/baselines/`
  - [ ] Naming : `<hostname>-<YYYY-MM-DD>.json`
  - [ ] `spira diff --auto` compare à la baseline du dernier scan
  - [ ] Rétention configurable (défaut : 30 jours)
- [ ] **Rapport de diff**
  - [ ] Format terminal coloré (rouge=new, vert=resolved)
  - [ ] Format Markdown pour rapports de change
  - [ ] Format JSON pour intégration alerting
- [ ] **Tests**
  - [ ] Test de diff entre deux scans synthétiques
  - [ ] Test de rétention (rotation automatique après 30 j)
  - [ ] Test compatibilité baseline JSON / SARIF / Markdown

### Livrables

- `spira diff` répond en < 100 ms sur 1000 findings
- Intégration CI : alerte sur nouvelles CVE critical/high depuis dernier build
- Workflow type : `cron` quotidien + `spira diff --auto --alert slack`

---

## Phase 14 — Compliance CIS Benchmarks *(Semaines 23-26)*

**Objectif :** Implémenter les contrôles CIS pour les principales distros,
avec scoring de conformité et remédiations actionnables.

### Tâches

- [ ] **Moteur de rules générique**
  - [ ] Struct `ComplianceRule { id, title, severity, audit_fn, remediate_fn }`
  - [ ] DSL interne simple (pas de CEL/Rego) : `audit()` retourne `RuleResult`
  - [ ] Catégorisation : `Pass`, `Fail`, `Manual`, `NotApplicable`
  - [ ] Stockage des règles en Rust (compile-time) ou TOML (extensibles)
- [ ] **CIS Debian 12 Benchmark** (priorité 1)
  - [ ] Section 1 (Initial Setup) : bootloader, filesystem, modules
  - [ ] Section 3 (Network) : paramètres kernel, IPv6, TCP wrappers
  - [ ] Section 5 (Access, Authentication) : PAM, password policy
  - [ ] Section 6 (SSH) : déjà couvert par audit/ssh, mapping vers CIS IDs
- [ ] **CIS Ubuntu 22.04 LTS** (priorité 2)
  - [ ] Réutilisation règles Debian quand identiques
  - [ ] Spécificités Ubuntu (snap, motd, cloud-init)
- [ ] **CIS RHEL 9 / Fedora 39** (priorité 3)
  - [ ] SELinux state enforcement
  - [ ] Auditd configuration
  - [ ] Systemd service activation
- [ ] **Sous-commande `spira compliance`**
  - [ ] `spira compliance --benchmark cis-debian-12`
  - [ ] Profils : `Level 1` (server), `Level 2` (workstation)
  - [ ] Output : score global % + détail par règle
  - [ ] `--format json|html|markdown`
  - [ ] Export au format [OpenSCAP](https://www.open-scap.org/) pour compatibilité
- [ ] **Remédiation**
  - [ ] Pour chaque règle, message de remédiation clair (sans exécution auto)
  - [ ] Lien vers documentation CIS officielle
  - [ ] Script shell généré à la demande (`--generate-fix-script`)
- [ ] **Tests**
  - [ ] Containers Docker (Debian 12, Ubuntu 22.04, RHEL 9) en CI
  - [ ] Snapshot score attendu pour chaque container
  - [ ] Test idempotence (run 2x = même score)

### Livrables

- `spira compliance --benchmark cis-debian-12 --level 1` retourne score détaillé
- Comparable à OpenSCAP en couverture mais 10× plus rapide
- Documentation : matrice des benchmarks supportés

---

## Phase 15 — Écosystème & distribution *(Semaines 27-28)*

**Objectif :** Maximiser l'adoption : templates CI, packages natifs,
distribution simplifiée.

### Tâches

- [ ] **Templates CI/CD**
  - [ ] `.github/workflows/security.yml` (GitHub Actions + upload SARIF)
  - [ ] `.gitlab-ci.yml` (GitLab + artifact JSON/SARIF)
  - [ ] Exemple Jenkins `Jenkinsfile`
  - [ ] Exemple Woodpecker CI `.woodpecker.yaml`
  - [ ] Tous paramétrables : sévérité minimale, format, profil
- [ ] **Packaging natif**
  - [ ] Paquet Debian (.deb) — déjà amorcé dans le repo
  - [ ] Paquet RPM via COPR Fedora
  - [ ] PKGBUILD pour AUR Arch
  - [ ] Formule Homebrew
  - [ ] Image Docker slim (`FROM debian:stable-slim`)
- [ ] **Distribution Docker**
  - [ ] `docker run --rm -v /etc:/etc:ro aerab/spira scan`
  - [ ] Mode multi-host : scan à distance via SSH (clé publique uniquement)
  - [ ] Compose file pour cron de scan quotidien
- [ ] **Documentation**
  - [ ] Page `docs/integrations.md` : matrix des intégrations supportées
  - [ ] Page `docs/best-practices.md` : usage CI/CD
  - [ ] Tutoriels : `docs/tutorials/01-first-scan.md`
  - [ ] FAQ : `docs/faq.md`
- [ ] **Communauté**
  - [ ] `CONTRIBUTING.md` détaillé (déjà existant, à enrichir)
  - [ ] `CODE_OF_CONDUCT.md`
  - [ ] Templates d'issues (bug, feature, question)
  - [ ] Templates de PR
  - [ ] Badge "good first issue" sur issues débutantes
- [ ] **Release v2.0**
  - [ ] Changelog détaillé
  - [ ] Migration guide depuis v1.x
  - [ ] Annonce blog / Hacker News / Reddit / r/netsec

### Livrables

- One-liner install : `brew install spira` / `apt install spira`
- Workflow GitHub prêt à copier-coller
- Image Docker multi-arch (amd64, arm64) sur Docker Hub
- v2.0.0 publiée avec annonce publique

---

## 📊 Métriques de succès globales

| Métrique                              | Objectif v2.0 |
| ------------------------------------- | ------------- |
| Temps de scan complet (1000 paquets)  | < 30 s        |
| Taux de faux négatifs (vs distros)    | < 5 %         |
| Distributions supportées              | 8+            |
| Sources CVE                           | 5+            |
| Intégrations CI/CD documentées        | 4+            |
| Couverture tests                      | > 80 %        |
| Stars GitHub                          | 500+          |
| Contributeurs externes                | 10+           |

---

## 🗓️ Calendrier macroscopique

```
S11  ▓▓▓░░░░░░░░░░░░░░░░░  Phase 7  (Observabilité & UX)
S12  ░▓▓▓▓░░░░░░░░░░░░░░░░  Phase 8a (Async)
S13  ░░▓▓▓░░░░░░░░░░░░░░░░  Phase 8b (SQLite hardening)
S14  ░░░▓▓▓░░░░░░░░░░░░░░░  Phase 9  (Config & profils)
S15  ░░░░▓▓▓░░░░░░░░░░░░░░  Phase 10a (DSA + USN)
S16  ░░░░░▓▓▓░░░░░░░░░░░░░  Phase 10b (RHSA + Arch)
S17  ░░░░░░▓▓▓░░░░░░░░░░░░  Phase 10c (Unification)
S18  ░░░░░░░▓▓▓░░░░░░░░░░░  Phase 11a (EPSS)
S19  ░░░░░░░░▓▓▓░░░░░░░░░░  Phase 11b (Exploits)
S20  ░░░░░░░░░▓▓▓░░░░░░░░░  Phase 12 (SARIF)
S21  ░░░░░░░░░░▓▓▓░░░░░░░░  Phase 13a (Diff core)
S22  ░░░░░░░░░░░▓▓▓░░░░░░░  Phase 13b (Stockage + tests)
S23  ░░░░░░░░░░░░▓▓▓░░░░░░  Phase 14a (CIS Debian/Ubuntu)
S24  ░░░░░░░░░░░░░▓▓▓░░░░░░  Phase 14a (suite)
S25  ░░░░░░░░░░░░░░▓▓▓░░░░  Phase 14b (CIS RHEL)
S26  ░░░░░░░░░░░░░░░▓▓▓░░░  Phase 14c (Tests + CI containers)
S27  ░░░░░░░░░░░░░░░░▓▓▓░░  Phase 15a (Templates + packaging)
S28  ░░░░░░░░░░░░░░░░░▓▓▓░  Phase 15b (Release v2.0)
```

---

## 🔗 Dépendances inter-phases

```
v1.0 ─► 7 ─┬─► 8 ─┬─► 10 ─► 11
           │      │            │
           ├─► 9  │            ├─► 13 ─► v2.0
           │      ├─► 12 ─────┘
           │      └─► 14 ──────┘
           └─► 15 ─────────────┘
```

**Chemin critique :** `7 → 8 → 10 → 13` (sources distro + drift = valeur maximale)

**Quick wins parallèles :** `9` et `15` peuvent démarrer dès la fin de la
phase 7 sans bloquer le chemin critique.

---

## 💡 Idées complémentaires (backlog)

Pour ne rien perdre, voici d'autres pistes identifiées mais non planifiées :

| Idée                                          | Pourquoi intéressant       | Effort |
| --------------------------------------------- | -------------------------- | ------ |
| Plugin system (`.wasm` ou dynamic loading)    | Extensibilité communautaire | Très haut |
| Interface Tauri (GUI desktop)                 | Adoption non-CLI           | Très haut |
| Scan réseau actif (nmap-style)                | CVE sur services distants  | Haut    |
| Scan conteneurs (Docker/Podman images)        | Sécurité supply chain      | Moyen   |
| Intégration SIEM (Splunk/Elastic/Loki)        | Usage enterprise           | Moyen   |
| Mode "watch" (scan continu avec alertes)      | Détection temps réel       | Moyen   |
| Notifications desktop / email / webhook       | Alerting réactif           | Bas     |
| Support macOS / *BSD                          | Élargir l'audience         | Moyen   |
| Base de règles personnalisée (TOML/YAML)      | Audits métier sur mesure   | Moyen   |
| Mode "agent" léger pour parc de serveurs      | Scan centralisé            | Haut    |
| Corrélation CVE ↔ KB distro ↔ changelog       | Aide à la remédiation      | Moyen   |
| Export PDF du rapport HTML                    | Reporting client-friendly  | Bas     |

Ces idées seront priorisées à chaque cycle de release (toutes les 6-8 semaines).

---

## 📝 Notes finales

- **Sprints** : 2 semaines par phase, démo interne à chaque fin de phase
- **Releases mineures** : tous les 2-3 mois (`v1.1`, `v1.2`, etc.)
- **Releases majeures** : tous les 6-9 mois (`v2.0`, `v3.0`, etc.)
- **Compatibilité** : engagement de compatibilité du schéma de cache entre versions mineures
- **Feedback loop** : GitHub Discussions pour valider chaque phase avant démarrage

> ℹ️ Ce roadmap est **vivant** : à mettre à jour à chaque fin de phase et
> après chaque release. Voir `PLAN.md` pour le contexte historique (Phases 0-6).
