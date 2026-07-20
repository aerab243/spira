use iced::{
    widget::{
        button, column, container, horizontal_rule, row, scrollable, text,
        Column,
    },
    Alignment, Color, Element, Fill, FillPortion, Task, Theme,
};
use spira_core::types::{ScanConfig, ScanResult, SystemInfo, Tab};

/// Lance l'application graphique Spira.
pub fn run() -> iced::Result {
    iced::application("Spira — Scanner de Vulnérabilités", update, view)
        .window(iced::window::Settings {
            size: iced::Size::new(1100.0, 750.0),
            min_size: Some(iced::Size::new(800.0, 600.0)),
            ..Default::default()
        })
        .run_with(initialize)
}

/// État global de l'application.
#[derive(Debug, Default)]
pub struct SpiraApp {
    /// Onglet actif
    pub active_tab: Tab,
    /// Informations système (chargées au démarrage)
    pub system_info: Option<SystemInfo>,
    /// Configuration du scan
    pub scan_config: ScanConfig,
    /// Résultat du dernier scan
    pub scan_result: Option<ScanResult>,
    /// Progression du scan en cours (0.0 à 1.0)
    pub scan_progress: f32,
    /// Message de statut du scan
    pub scan_status: String,
    /// Indique si un scan est en cours
    pub is_scanning: bool,
    /// Vulnérabilité sélectionnée dans la liste des résultats
    pub selected_vuln_index: Option<usize>,
}

/// Messages que l'application peut recevoir.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Message {
    /// Changement d'onglet
    TabChanged(Tab),
    /// Démarrage d'un scan
    ScanStarted,
    /// Mise à jour de la progression du scan
    ScanProgress(f32, String),
    /// Scan terminé avec des résultats
    ScanCompleted(ScanResult),
    /// Erreur pendant le scan
    ScanError(String),
    /// Informations système chargées
    SystemInfoLoaded(SystemInfo),
    /// Configuration modifiée
    ConfigChanged(ScanConfig),
    /// Vulnérabilité sélectionnée dans les résultats
    VulnerabilitySelected(usize),
}

/// Initialise l'état de l'application et retourne la tâche de démarrage.
fn initialize() -> (SpiraApp, Task<Message>) {
    let app = SpiraApp::default();
    let task = Task::perform(
        spira_core::system::collect_system_info(),
        |result| match result {
            Ok(info) => Message::SystemInfoLoaded(info),
            Err(e) => Message::ScanError(e.to_string()),
        },
    );
    (app, task)
}

/// Met à jour l'état de l'application en réponse à un message.
fn update(state: &mut SpiraApp, message: Message) -> Task<Message> {
    match message {
        Message::TabChanged(tab) => {
            state.active_tab = tab;
        }
        Message::ScanStarted => {
            state.is_scanning = true;
            state.scan_progress = 0.0;
            state.scan_status = "Initialisation du scan...".to_string();
            state.scan_result = None;
            // TODO Phase 4-7: Lancer les scanners
        }
        Message::ScanProgress(progress, status) => {
            state.scan_progress = progress;
            state.scan_status = status;
        }
        Message::ScanCompleted(result) => {
            state.is_scanning = false;
            state.scan_progress = 1.0;
            state.scan_status = "Scan terminé".to_string();
            state.scan_result = Some(result);
            state.active_tab = Tab::Results;
        }
        Message::ScanError(err) => {
            state.is_scanning = false;
            state.scan_status = format!("Erreur : {}", err);
        }
        Message::SystemInfoLoaded(info) => {
            state.system_info = Some(info);
        }
        Message::ConfigChanged(config) => {
            state.scan_config = config;
        }
        Message::VulnerabilitySelected(index) => {
            state.selected_vuln_index = Some(index);
        }
    }
    Task::none()
}

/// Construit l'interface utilisateur à partir de l'état courant.
fn view(state: &SpiraApp) -> Element<'_, Message> {
    let sidebar = view_sidebar(state);
    let content = view_content(state);

    container(row![sidebar, content].width(Fill).height(Fill))
        .width(Fill)
        .height(Fill)
        .into()
}

// ─── Fonctions utilitaires de style ──────────────────────────────────

/// Crée un style de carte arrondie avec fond légèrement surélevé.
fn card_style(theme: &Theme) -> container::Style {
    let palette = theme.extended_palette();
    container::Style {
        background: Some(palette.background.weak.color.into()),
        border: iced::Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Crée un style de fond sombre (pour la barre latérale).
fn dark_bg_style(theme: &Theme) -> container::Style {
    let palette = theme.extended_palette();
    container::Style {
        background: Some(Color::from_rgb(0.08, 0.08, 0.10).into()),
        text_color: Some(palette.background.base.text),
        ..Default::default()
    }
}

// ─── Navigation latérale ─────────────────────────────────────────────

fn view_sidebar(state: &SpiraApp) -> Element<'_, Message> {
    let tabs: &[(Tab, &str)] = &[
        (Tab::Dashboard, "📊 Tableau de bord"),
        (Tab::Scan, "🔍 Analyse"),
        (Tab::Results, "📋 Résultats"),
        (Tab::Reports, "📄 Rapports"),
        (Tab::Settings, "⚙️ Paramètres"),
        (Tab::About, "ℹ️ À propos"),
    ];

    let mut col = Column::new()
        .spacing(4)
        .padding(12)
        .width(200)
        .push(
            text("🔬")
                .size(32)
                .width(Fill)
                .align_x(iced::alignment::Horizontal::Center),
        )
        .push(
            text("Spira")
                .size(22)
                .width(Fill)
                .align_x(iced::alignment::Horizontal::Center),
        )
        .push(
            text("v0.1.0")
                .size(12)
                .color(Color::from_rgb(0.5, 0.5, 0.5)),
        )
        .push(horizontal_rule(8));

    for (tab, label) in tabs {
        let is_active = *tab == state.active_tab;
        let btn = button(
            text(if is_active {
                format!("▸ {}", label)
            } else {
                format!("  {}", label)
            })
            .size(14)
            .width(Fill),
        )
        .width(Fill)
        .style(move |theme, status| {
            if is_active {
                button::primary(theme, status)
            } else {
                button::text(theme, status)
            }
        })
        .on_press(Message::TabChanged(*tab));

        col = col.push(btn);
    }

    // Infos système dans le bas de la sidebar
    if let Some(info) = &state.system_info {
        col = col
            .push(horizontal_rule(8))
            .push(
                text(info.os.clone())
                    .size(10)
                    .color(Color::from_rgb(0.5, 0.5, 0.5)),
            )
            .push(
                text(format!("Kernel: {}", info.kernel_version))
                    .size(10)
                    .color(Color::from_rgb(0.5, 0.5, 0.5)),
            );
    }

    container(col).style(dark_bg_style).height(Fill).into()
}

fn view_content(state: &SpiraApp) -> Element<'_, Message> {
    let content: Element<Message> = match state.active_tab {
        Tab::Dashboard => view_dashboard(state),
        Tab::Scan => view_scan(state),
        Tab::Results => view_results(state),
        Tab::Reports => view_reports(state),
        Tab::Settings => view_settings(state),
        Tab::About => view_about(state),
    };

    container(
        scrollable(
            column![]
                .push(text("").size(16))
                .push(content)
                .padding(24)
                .spacing(16),
        ),
    )
    .height(Fill)
    .into()
}

// ─── Dashboard ──────────────────────────────────────────────────

fn view_dashboard(state: &SpiraApp) -> Element<'_, Message> {
    let mut col = Column::new().spacing(24);

    col = col.push(text("📊 Tableau de bord").size(26));

    // Carte infos système
    if let Some(info) = &state.system_info {
        let sys_card = column![
            text("💻 Système").size(18),
            horizontal_rule(4),
            text(format!("OS: {}", info.os)).size(14),
            text(format!("Kernel: {}", info.kernel_version)).size(14),
            text(format!("Hostname: {}", info.hostname)).size(14),
            text(format!("Paquets installés: {}", info.packages_count)).size(14),
            text(format!("Uptime: {}h", info.uptime_seconds / 3600)).size(14),
        ]
        .spacing(4)
        .padding(16);

        col = col.push(container(sys_card).style(card_style).width(Fill));
    }

    // Carte statut du scan
    let scan_card = column![
        text("🔍 Dernière analyse").size(18),
        horizontal_rule(4),
        text(match &state.scan_result {
            Some(result) => format!(
                "✓ Scan terminé — {} vulnérabilités trouvées ({})",
                result.stats.total, result.scan_time_ms
            ),
            None => "Aucune analyse effectuée".to_string(),
        })
        .size(14),
    ]
    .spacing(4)
    .padding(16);

    col = col.push(container(scan_card).style(card_style).width(Fill));

    // Boutons d'action
    col = col.push(
        row![
            button(
                text("🔍 Lancer une analyse rapide")
                    .size(16)
                    .width(Fill)
                    .align_x(iced::alignment::Horizontal::Center)
            )
            .padding(12)
            .width(Fill)
            .on_press(Message::TabChanged(Tab::Scan)),
            button(
                text("📋 Voir les résultats")
                    .size(16)
                    .width(Fill)
                    .align_x(iced::alignment::Horizontal::Center)
            )
            .padding(12)
            .width(Fill)
            .on_press(Message::TabChanged(Tab::Results)),
        ]
        .spacing(12),
    );

    col.into()
}

// ─── Scan ───────────────────────────────────────────────────────

fn view_scan(state: &SpiraApp) -> Element<'_, Message> {
    let mut col = Column::new().spacing(16);

    col = col.push(text("🔍 Analyse de sécurité").size(26));

    col = col.push(
        text("Sélectionnez les vérifications à effectuer, puis lancez l'analyse.")
            .size(14)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
    );

    col = col.push(horizontal_rule(8));

    // Liste des vérifications disponibles
    let checks = [
        ("📦 Paquets", "Vérifie les paquets contre les bases CVE"),
        ("🔌 Réseau", "Analyse les ports ouverts et services"),
        ("🔐 Permissions", "Recherche les permissions dangereuses"),
        ("🐧 Kernel", "Vérifie la version du kernel"),
        ("👥 Utilisateurs", "Analyse les comptes utilisateurs"),
        ("🔥 Pare-feu", "Vérifie la configuration du firewall"),
        ("📋 Journaux", "Analyse les logs d'authentification"),
        ("🧪 Rootkits", "Recherche les signes de rootkits"),
    ];

    for (name, desc) in &checks {
        let check = row![
            text(*name).size(14).width(FillPortion(1)),
            text(*desc)
                .size(12)
                .color(Color::from_rgb(0.5, 0.5, 0.5))
                .width(FillPortion(2)),
        ]
        .spacing(8)
        .padding(8);

        col = col.push(container(check).style(card_style).width(Fill));
    }

    col = col.push(horizontal_rule(8));

    // Progression (si scan en cours)
    if state.is_scanning {
        col = col.push(
            container(
                column![
                    text(format!(
                        "Progression: {:.0}%",
                        state.scan_progress * 100.0
                    ))
                    .size(14),
                    text(&state.scan_status).size(12),
                ]
                .spacing(4),
            )
            .padding(16)
            .style(card_style),
        );
    }

    // Bouton de lancement
    col = col.push(
        button(
            text(if state.is_scanning {
                "⏳ Scan en cours..."
            } else {
                "🚀 Lancer l'analyse"
            })
            .size(18)
            .width(Fill)
            .align_x(iced::alignment::Horizontal::Center),
        )
        .padding(16)
        .width(Fill)
        .style(button::primary)
        .on_press(Message::ScanStarted),
    );

    col.into()
}

// ─── Results ────────────────────────────────────────────────────

fn view_results(state: &SpiraApp) -> Element<'_, Message> {
    let mut col = Column::new().spacing(16);

    col = col.push(text("📋 Résultats de l'analyse").size(26));

    match &state.scan_result {
        Some(result) => {
            col = col.push(
                text(format!("Total: {} vulnérabilités trouvées", result.stats.total))
                    .size(16),
            );

            if !result.vulnerabilities.is_empty() {
                for (i, vuln) in result.vulnerabilities.iter().enumerate() {
                    let severity_color = match vuln.severity {
                        spira_core::types::Severity::Critical => {
                            Color::from_rgb(0.9, 0.2, 0.2)
                        }
                        spira_core::types::Severity::High => {
                            Color::from_rgb(0.9, 0.5, 0.1)
                        }
                        spira_core::types::Severity::Medium => {
                            Color::from_rgb(0.9, 0.8, 0.1)
                        }
                        spira_core::types::Severity::Low => {
                            Color::from_rgb(0.4, 0.8, 0.4)
                        }
                        spira_core::types::Severity::Info => {
                            Color::from_rgb(0.5, 0.5, 0.8)
                        }
                    };

                    let item = row![
                        text(format!(
                            "{} {:7}",
                            vuln.scan_type.icon(),
                            vuln.severity.label()
                        ))
                        .size(13)
                        .color(severity_color)
                        .width(FillPortion(2)),
                        text(&vuln.id).size(13).width(FillPortion(3)),
                        text(&vuln.package).size(13).width(FillPortion(2)),
                        text(format!("CVSS: {:.1}", vuln.cvss_score))
                            .size(13)
                            .width(FillPortion(1)),
                    ]
                    .spacing(8)
                    .padding(8);

                    col = col.push(
                        button(item)
                            .width(Fill)
                            .style(button::text)
                            .on_press(Message::VulnerabilitySelected(i)),
                    );
                }
            } else {
                col = col.push(
                    container(
                        text("✅ Aucune vulnérabilité détectée. Votre système semble sécurisé !")
                            .size(14),
                    )
                    .padding(24)
                    .style(card_style),
                );
            }
        }
        None => {
            col = col.push(
                container(
                    column![
                        text("Aucun résultat disponible").size(18),
                        text("Lancez une analyse depuis l'onglet 'Analyse'.").size(14),
                        button(
                            text("🔍 Lancer une analyse")
                                .size(16)
                                .width(Fill)
                                .align_x(iced::alignment::Horizontal::Center)
                        )
                        .padding(12)
                        .style(button::primary)
                        .on_press(Message::TabChanged(Tab::Scan)),
                    ]
                    .spacing(8)
                    .align_x(Alignment::Center),
                )
                .padding(32)
                .width(Fill),
            );
        }
    }

    col.into()
}

// ─── Reports ────────────────────────────────────────────────────

fn view_reports(_state: &SpiraApp) -> Element<'_, Message> {
    let mut col = Column::new().spacing(16);

    col = col.push(text("📄 Rapports").size(26));

    col = col.push(
        text("Exportez les résultats d'analyse dans différents formats.")
            .size(14)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
    );

    col = col.push(horizontal_rule(8));

    // TODO Phase 7: Implémenter l'export de rapports
    let formats = ["JSON", "CSV", "HTML", "Texte"];
    for fmt in &formats {
        let card = row![
            text(format!("📄 {}", fmt)).size(14).width(Fill),
            button(text("Exporter").size(12)).padding(8).style(button::text),
        ]
        .spacing(8)
        .padding(12);

        col = col.push(container(card).style(card_style).width(Fill));
    }

    col.into()
}

// ─── Settings ───────────────────────────────────────────────────

fn view_settings(_state: &SpiraApp) -> Element<'_, Message> {
    let mut col = Column::new().spacing(16);

    col = col.push(text("⚙️ Paramètres").size(26));

    col = col.push(
        text("Configurez les options de scan et les préférences de l'application.")
            .size(14)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
    );

    col = col.push(horizontal_rule(8));

    // TODO Phase 7: Implémenter les paramètres avancés
    let settings = [
        ("📦 Scan des paquets", "Vérifier les paquets installés"),
        ("🔌 Scan réseau", "Analyser les ports ouverts"),
        ("🔐 Scan des permissions", "Vérifier les permissions"),
        ("🐧 Scan du kernel", "Vérifier la version du kernel"),
        ("👥 Scan des utilisateurs", "Analyser les comptes"),
        ("🔥 Scan du pare-feu", "Vérifier le firewall"),
        ("📋 Scan des logs", "Analyser les journaux"),
        ("🧪 Scan des rootkits", "Détection de rootkits"),
    ];

    for (name, desc) in &settings {
        let item = row![
            text(*name).size(14).width(FillPortion(1)),
            text(*desc)
                .size(12)
                .color(Color::from_rgb(0.5, 0.5, 0.5))
                .width(FillPortion(2)),
            text("🟢 Activé")
                .size(12)
                .color(Color::from_rgb(0.3, 0.8, 0.3)),
        ]
        .spacing(8)
        .padding(8);

        col = col.push(container(item).style(card_style).width(Fill));
    }

    col.into()
}

// ─── About ──────────────────────────────────────────────────────

fn view_about(_state: &SpiraApp) -> Element<'_, Message> {
    column![
        text("ℹ️ À propos de Spira").size(26),
        horizontal_rule(8),
        text("Spira v0.1.0").size(18),
        text("Scanner de vulnérabilités pour Linux").size(14),
        text("").size(8),
        text("Développé avec Rust et Iced").size(14),
        text(
            "Spira vérifie la sécurité de votre système Ubuntu/Linux en analysant :"
        )
        .size(14),
        text("• Les paquets installés contre les bases CVE").size(13),
        text("• Les ports réseau ouverts et services exposés").size(13),
        text("• Les permissions dangereuses (SUID, SGID)").size(13),
        text("• La version du kernel").size(13),
        text("• Les comptes utilisateurs et mots de passe").size(13),
        text("• La configuration du pare-feu").size(13),
        text("• Les journaux d'authentification").size(13),
        text("• Les signes de rootkits").size(13),
    ]
    .spacing(4)
    .into()
}
