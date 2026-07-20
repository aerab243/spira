# 🔬 Spira — Security Vulnerability Scanner

**Spira** est un scanner de vulnérabilités pour Linux (Ubuntu en priorité) développé en Rust.

Il vérifie plusieurs aspects de la sécurité de votre système :
- 📦 **Paquets** — Comparaison des paquets installés avec les bases CVE
- 🔌 **Réseau** — Ports ouverts et services exposés
- 🔐 **Permissions** — Fichiers SUID/SGID, permissions dangereuses
- 🐧 **Kernel** — Version du kernel et CVEs connues
- 👥 **Utilisateurs** — Comptes, mots de passe et privilèges
- 🔥 **Pare-feu** — Configuration iptables/nftables
- 📋 **Journaux** — Analyse des logs d'authentification
- 🧪 **Rootkits** — Signes de malwares et rootkits

## 🚀 Pour commencer

### Prérequis

- [Rust](https://www.rust-lang.org/tools/install) 1.75 ou plus récent
- Ubuntu 22.04+ (recommandé)

### Installation rapide

```bash
git clone https://github.com/votre-compte/spira.git
cd spira
./scripts/install.sh
```

### Développement

```bash
# Lancer l'interface graphique
cargo run

# Build release
cargo build --release
./target/release/spira-gui
```

## 🏗️ Structure du projet

```
spira/
├── Cargo.toml               # Workspace racine
├── spira-core/              # Bibliothèque cœur (logique métier)
│   ├── src/
│   │   ├── lib.rs           # Point d'entrée du crate
│   │   ├── types.rs         # Types fondamentaux
│   │   ├── scanners/        # Moteurs de scan
│   │   ├── cve/             # Base de vulnérabilités CVE
│   │   └── system/          # Informations système
├── spira-gui/               # Interface graphique (Iced)
│   ├── src/
│   │   ├── main.rs          # Point d'entrée
│   │   └── app.rs           # Application Iced
└── scripts/                 # Scripts utilitaires
```

## 🧰 Stack technique

| Composant | Technologie |
|-----------|-------------|
| Langage | Rust (1.75+) |
| GUI | [Iced](https://iced.rs/) 0.13 |
| Parsing XML | quick-xml |
| HTTP | reqwest |
| Async | Tokio |
| Sérialisation | Serde |

## 📋 Phases du projet

- [x] **Phase 1** — Structure du projet, workspace, types fondamentaux
- [ ] **Phase 2** — Module système (infos OS, paquets)
- [ ] **Phase 3** — Module CVE (base de données OVAL Ubuntu)
- [ ] **Phase 4** — Tous les scanners (packages, network, permissions...)
- [ ] **Phase 5** — Interface graphique complète avec Iced
- [ ] **Phase 6** — Dashboard, progression de scan, temps réel
- [ ] **Phase 7** — Résultats détaillés, filtres, export de rapports
- [ ] **Phase 8** — Tests, packaging .deb, documentation

## 📄 Licence

MIT
