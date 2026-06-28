// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "spira")]
#[command(
    about = "Outil d'analyse de vulnérabilités pour systèmes Linux",
    long_about = "Spira détecte la distribution, scanne les paquets installés, \
                  croise les versions avec la base NVD, audite la configuration \
                  système (SSH, firewall, sudoers) et produit des rapports \
                  multi-formats (terminal, JSON, HTML, Markdown)."
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Chemin du fichier de sortie (par défaut: stdout).
    #[arg(short, long, global = true)]
    pub output: Option<String>,

    /// Mode hors-ligne: ne contacte pas les flux NVD distants.
    #[arg(long, global = true)]
    pub offline: bool,

    /// Sortie JSON raccourcie (équivalent à --format json pour detect/packages).
    #[arg(short, long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Détecte la distribution, le noyau et le gestionnaire de paquets.
    #[command(
        about = "Détecte la distribution Linux, le noyau et le gestionnaire de paquets",
        long_about = "Lit /etc/os-release pour identifier la distribution, \
                      /proc/version pour le noyau, et détecte le gestionnaire \
                      de paquets disponible (dpkg, rpm, pacman, apk)."
    )]
    Detect {
        /// Afficher les informations détaillées sur le noyau.
        #[arg(long)]
        kernel: bool,

        /// Afficher les informations sur le gestionnaire de paquets.
        #[arg(long)]
        packages: bool,
    },

    /// Liste tous les paquets installés sur le système.
    #[command(
        about = "Liste tous les paquets installés via le gestionnaire détecté",
        long_about = "Interroge dpkg/rpm/pacman/apk selon le gestionnaire présent \
                      sur le système et affiche la liste complète des paquets \
                      installés avec leur version."
    )]
    Packages,

    /// Lance un scan complet de vulnérabilités (paquets + noyau + services + ports).
    #[command(
        about = "Scan complet: paquets, noyau, services actifs et ports ouverts",
        long_about = "Croise la liste des paquets installés et la version du noyau \
                      avec le cache CVE local (NVD). Détecte les services en cours \
                      d'exécution (systemctl) et les ports ouverts (ss), puis \
                      identifie les CVE correspondantes via heuristiques sur les \
                      noms de processus et les alias de ports."
    )]
    Scan {
        /// Inclure le scan des vulnérabilités du noyau Linux.
        #[arg(long, default_value_t = true)]
        kernel: bool,

        /// Inclure la détection des services et l'analyse des ports ouverts.
        #[arg(long, default_value_t = true)]
        services: bool,

        /// Format du rapport: terminal, json, html, markdown.
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Limite l'affichage aux N CVE les plus critiques (0 = tout afficher).
        #[arg(long, default_value_t = 0)]
        max_cve: usize,
    },

    /// Audit de configuration: SSH, firewall (iptables/nftables/firewalld/ufw) et sudoers.
    #[command(
        about = "Audit de configuration: SSH, firewall et sudoers",
        long_about = "Analyse les fichiers de configuration système et produit un \
                      score de sécurité:\n  - SSH: PermitRootLogin, PasswordAuthentication, \
                      PubkeyAuthentication, PermitEmptyPasswords, etc.\n  - Firewall: \
                      détection et règles iptables/nftables/firewalld/ufw.\n  - Sudoers: \
                      présence de NOPASSWD, !authenticate, secure_path, etc."
    )]
    Audit {
        /// Format du rapport: terminal, json, html, markdown.
        #[arg(short, long, default_value = "terminal")]
        format: String,
    },

    /// Affiche les CVE connues pour un paquet donné.
    #[command(
        about = "Cherche les CVE connues pour un paquet",
        long_about = "Interroge le cache CVE local pour trouver toutes les \
                      vulnérabilités associées au nom de paquet fourni, triées \
                      par score CVSS décroissant."
    )]
    Vulns {
        /// Nom du paquet à rechercher (ex: openssl, bash, nginx).
        name: String,
    },

    /// Met à jour le cache CVE local depuis les flux de données NVD.
    #[command(
        about = "Télécharge les flux CVE récents depuis NVD",
        long_about = "Télécharge les flux 'recent' (8 derniers jours) et 'modified' \
                      (CVE modifiés récemment) depuis le site du NVD, puis \
                      alimente le cache SQLite local. Nécessite une connexion \
                      Internet."
    )]
    Update,
}
