/// Module `cve` — Gestion des bases de données de vulnérabilités CVE/OVAL.
///
/// Ce module s'occupe de :
/// - Télécharger et mettre en cache la base OVAL Ubuntu
/// - Parser les fichiers XML OVAL (format Canonical)
/// - Faire correspondre les paquets installés avec les CVE connues
///
/// # Format OVAL Ubuntu
///
/// Canonical publie des flux OVAL compressés en bzip2 :
/// `https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2`
///
/// ## Structure XML
///
/// - `<definitions>` — Chaque `<definition>` correspond à une CVE
///   - `<metadata>` : titre, description, sévérité, score CVSS
///   - `<criteria>` : référence les `<criterion test_ref="..." />`
/// - `<tests>` — Tests dpkginfo_test
///   - `object_ref` → package name (via variables)
///   - `state_ref` → version fixe (optionnel)
/// - `<objects>` — Référence les variables contenant les noms de paquets
/// - `<states>` — Conditions de version (`evr operation="less than"`)
/// - `<variables>` — Noms concrets des paquets (`constant_variable`)

use crate::types::{ScanError, Severity, Vulnerability, ScanType};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::Command;

// ─── Constantes ─────────────────────────────────────────────────────

/// URL de base pour les flux OVAL Canonical.
const OVAL_BASE_URL: &str = "https://security-metadata.canonical.com/oval/com.ubuntu";

/// Nom du répertoire de cache dans le répertoire de configuration.
const CACHE_DIR_NAME: &str = "spira/cve_cache";

/// Durée de validité du cache en secondes (24h).
const CACHE_TTL_SECS: u64 = 86400;

// ─── Structures de données internes ─────────────────────────────────

/// Entrée CVE résolue, associée à un paquet spécifique.
#[derive(Debug, Clone)]
pub struct CveEntry {
    /// Identifiant CVE (ex: CVE-2024-XXXX).
    pub cve_id: String,
    /// Sévérité de la vulnérabilité.
    pub severity: Severity,
    /// Score CVSS (0.0 si non disponible).
    pub cvss_score: f32,
    /// Description détaillée de la vulnérabilité.
    pub description: String,
    /// Version dans laquelle le correctif a été publié.
    pub fixed_version: Option<String>,
    /// Instruction de mise à jour (optionnelle).
    pub remediation: Option<String>,
}

// ─── Structures OVAL internes (parsing) ─────────────────────────────

/// Une définition OVAL brute (avant résolution des références).
#[derive(Debug, Default)]
struct OvalDefinitionRaw {
    id: String,
    cve_id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    cvss_score: Option<f32>,
    test_refs: Vec<String>,
}

/// Un test dpkginfo OVAL brut.
#[derive(Debug, Default)]
struct OvalTestRaw {
    id: String,
    object_ref: Option<String>,
    state_ref: Option<String>,
}

/// Un objet dpkginfo OVAL brut (pointe vers une variable).
#[derive(Debug, Default)]
struct OvalObjectRaw {
    id: String,
    var_ref: Option<String>,
}

/// Un état dpkginfo OVAL brut (condition de version).
#[derive(Debug, Default)]
struct OvalStateRaw {
    id: String,
    operation: Option<String>,
    version: Option<String>,
}

/// Une variable OVAL.
#[derive(Debug)]
enum OvalVariable {
    Constant { id: String, values: Vec<String> },
    Local { id: String },
}

/// État du parsing OVAL — quelle section on traverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Definitions,
    Tests,
    Objects,
    States,
    Variables,
}

// ─── Gestionnaire principal ─────────────────────────────────────────

/// Gestionnaire de la base de données CVE/OVAL.
///
/// Télécharge le flux OVAL Ubuntu, le parse et construit un index
/// pour retrouver rapidement les CVE associées à chaque paquet.
pub struct CveDatabase {
    /// Index : nom_de_paquet → liste d'entrées CVE
    entries: HashMap<String, Vec<CveEntry>>,
    /// Indique si la base est initialisée et prête.
    pub initialized: bool,
    /// Date de la dernière mise à jour.
    pub last_update: Option<String>,
    /// Code name de la distribution Ubuntu ciblée.
    pub source_codename: String,
    /// Nombre total d'entrées CVE dans la base.
    total_entries: usize,
}

impl CveDatabase {
    /// Crée une nouvelle instance de la base CVE.
    ///
    /// Par défaut, tente de détecter le codename Ubuntu via `lsb_release -cs`.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            initialized: false,
            last_update: None,
            source_codename: String::new(),
            total_entries: 0,
        }
    }

    /// Crée une instance avec un codename Ubuntu explicite.
    pub fn with_codename(codename: &str) -> Self {
        Self {
            entries: HashMap::new(),
            initialized: false,
            last_update: None,
            source_codename: codename.to_string(),
            total_entries: 0,
        }
    }

    /// Initialise la base de données : détecte la distribution, télécharge
    /// le flux OVAL (ou utilise le cache), et parse le XML.
    pub async fn initialize(&mut self) -> Result<(), ScanError> {
        log::info!("Initialisation de la base CVE...");

        // 1. Détection du codename
        if self.source_codename.is_empty() {
            self.source_codename = detect_ubuntu_codename().await?;
        }
        log::info!("Distribution cible : Ubuntu {} ({})", self.source_codename, self.source_codename);

        // 2. Préparer le répertoire de cache
        let cache_dir = get_cache_dir()?;
        tokio::fs::create_dir_all(&cache_dir).await.map_err(|e| {
            ScanError::CveDatabaseError(format!(
                "Impossible de créer le cache {}: {}",
                cache_dir.display(),
                e
            ))
        })?;

        let oval_path = cache_dir.join(format!("com.ubuntu.{}.cve.oval.xml", self.source_codename));
        let bz2_path = oval_path.with_extension("xml.bz2");

        // 3. Vérifier le cache
        let needs_download = needs_cache_refresh(&oval_path);

        if needs_download {
            log::info!("Téléchargement du flux OVAL pour {}...", self.source_codename);
            match self.download_oval(&bz2_path).await {
                Ok(()) => {
                    log::info!("Décompression du flux OVAL...");
                    match decompress_bz2(&bz2_path, &oval_path).await {
                        Ok(()) => {
                            // Nettoyer le fichier compressé
                            let _ = tokio::fs::remove_file(&bz2_path).await;
                            log::info!("Flux OVAL décompressé : {}", oval_path.display());
                        }
                        Err(e) => {
                            log::warn!("Erreur de décompression : {}", e);
                            // Si on a déjà un cache, on l'utilise
                            if oval_path.exists() {
                                log::warn!("Utilisation du cache existant (périmé)");
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Erreur de téléchargement : {}", e);
                    // Si on a déjà un cache, on l'utilise
                    if oval_path.exists() {
                        log::warn!("Utilisation du cache existant (périmé)");
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            log::info!("Utilisation du cache OVAL : {}", oval_path.display());
        }

        // 4. Parser le fichier XML
        log::info!("Parsing du flux OVAL...");
        let (entries, count) = parse_oval_file(&oval_path).await?;
        self.entries = entries;
        self.total_entries = count;
        self.initialized = true;
        self.last_update = Some(chrono::Local::now().to_string());

        log::info!(
            "Base CVE initialisée : {} entrées pour {} paquets",
            self.total_entries,
            self.entries.len()
        );

        Ok(())
    }

    /// Vérifie si un paquet est concerné par une CVE connue.
    ///
    /// Compare la version installée du paquet avec les versions fixes
    /// déclarées dans la base OVAL. Si la version installée est inférieure
    /// à la version fixe, le paquet est vulnérable.
    pub async fn check_package(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<Vec<Vulnerability>, ScanError> {
        if !self.initialized {
            return Err(ScanError::CveDatabaseError(
                "Base CVE non initialisée. Appelez initialize() d'abord.".into(),
            ));
        }

        let Some(cve_entries) = self.entries.get(package_name) else {
            return Ok(Vec::new());
        };

        let mut vulnerabilities = Vec::new();

        for entry in cve_entries {
            let is_vulnerable = match &entry.fixed_version {
                Some(fixed) => {
                    // Si la version installée est STRICTEMENT inférieure à la version fixe
                    compare_deb_versions(package_version, fixed) == std::cmp::Ordering::Less
                }
                // Pas de version fixe déclarée → on signale la CVE
                None => true,
            };

            if is_vulnerable {
                vulnerabilities.push(Vulnerability {
                    id: entry.cve_id.clone(),
                    package: package_name.to_string(),
                    version: package_version.to_string(),
                    severity: entry.severity,
                    description: entry.description.clone(),
                    affected_version: package_version.to_string(),
                    fixed_version: entry.fixed_version.clone(),
                    cvss_score: entry.cvss_score,
                    scan_type: ScanType::Packages,
                    remediation: entry.remediation.clone().or_else(|| {
                        entry.fixed_version.as_ref().map(|v| {
                            format!(
                                "Mettez à jour le paquet '{}' vers la version {} (ou ultérieure)",
                                package_name, v
                            )
                        })
                    }),
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Vérifie si la base a besoin d'être mise à jour.
    pub fn needs_update(&self) -> bool {
        if !self.initialized {
            return true;
        }
        // Vérifie la fraîcheur du cache
        let cache_dir = match get_cache_dir() {
            Ok(d) => d,
            Err(_) => return true,
        };
        let oval_path = cache_dir.join(format!("com.ubuntu.{}.cve.oval.xml", self.source_codename));
        needs_cache_refresh(&oval_path)
    }

    /// Retourne le nombre d'entrées CVE dans la base.
    pub fn entries_count(&self) -> u32 {
        self.total_entries as u32
    }

    /// Retourne le nombre de paquets distincts dans l'index.
    pub fn packages_count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Télécharge le flux OVAL compressé.
    async fn download_oval(&self, dest: &Path) -> Result<(), ScanError> {
        let url = format!(
            "{}.{}.cve.oval.xml.bz2",
            OVAL_BASE_URL, self.source_codename
        );

        log::info!("Téléchargement depuis {}", url);

        let response = reqwest::get(&url)
            .await
            .map_err(|e| ScanError::NetworkError(format!("Échec du téléchargement OVAL: {}", e)))?;

        if !response.status().is_success() {
            return Err(ScanError::NetworkError(format!(
                "Échec du téléchargement OVAL: HTTP {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ScanError::NetworkError(format!("Erreur de lecture du flux: {}", e)))?;

        tokio::fs::write(dest, &bytes)
            .await
            .map_err(|e| ScanError::CveDatabaseError(format!("Échec de l'écriture du cache: {}", e)))?;

        log::info!("Fichier OVAL téléchargé : {} ({} Ko)", dest.display(), bytes.len() / 1024);
        Ok(())
    }
}

impl Default for CveDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Détection du système ───────────────────────────────────────────

/// Détecte le codename de la distribution Ubuntu via `lsb_release -cs`.
async fn detect_ubuntu_codename() -> Result<String, ScanError> {
    // Essayer lsb_release d'abord
    let output = Command::new("lsb_release")
        .arg("-cs")
        .output()
        .await
        .map_err(|_| ScanError::CommandError("lsb_release non trouvé".into()));

    if let Ok(output) = output {
        if output.status.success() {
            let codename = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !codename.is_empty() && codename != "n/a" {
                return Ok(codename);
            }
        }
    }

    // Fallback : /etc/os-release
    if let Ok(content) = tokio::fs::read_to_string("/etc/os-release").await {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("VERSION_CODENAME=") {
                let codename = val.trim_matches('"').to_string();
                if !codename.is_empty() {
                    return Ok(codename);
                }
            }
        }
    }

    Err(ScanError::CveDatabaseError(
        "Impossible de détecter la distribution Ubuntu. \
         Spécifiez le codename manuellement (ex: 'noble', 'jammy', 'focal')."
            .into(),
    ))
}

// ─── Gestion du cache ───────────────────────────────────────────────

/// Retourne le chemin du répertoire de cache.
fn get_cache_dir() -> Result<PathBuf, ScanError> {
    if let Ok(dir) = std::env::var("SPIRA_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }

    // Répertoires XDG standard
    if let Ok(cache_home) = std::env::var("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(cache_home).join(CACHE_DIR_NAME));
    }

    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".cache").join(CACHE_DIR_NAME));
    }

    // Fallback
    Ok(PathBuf::from("/tmp").join(CACHE_DIR_NAME))
}

/// Vérifie si le cache doit être rafraîchi.
fn needs_cache_refresh(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    if let Ok(metadata) = path.metadata() {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() > CACHE_TTL_SECS;
            }
        }
    }
    true
}

/// Décompresse un fichier `.bz2` en utilisant la commande système `bunzip2`.
async fn decompress_bz2(src: &Path, dest: &Path) -> Result<(), ScanError> {
    let status = Command::new("bunzip2")
        .arg("-c")
        .arg(src)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            ScanError::CommandError(format!(
                "Impossible d'exécuter bunzip2: {}. Installez bzip2 : sudo apt install bzip2",
                e
            ))
        })?;

    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        return Err(ScanError::CommandError(format!(
            "Erreur de décompression bzip2: {}",
            stderr
        )));
    }

    tokio::fs::write(dest, &status.stdout)
        .await
        .map_err(|e| ScanError::CveDatabaseError(format!("Échec d'écriture du fichier décompressé: {}", e)))?;

    Ok(())
}

// ─── Parsing OVAL XML ───────────────────────────────────────────────

/// Parse un fichier OVAL XML et retourne l'index paquet → CVE.
///
/// # Algorithme
///
/// 1. Parcours en streaming du XML pour extraire les 5 sections :
///    definitions, tests, objects, states, variables
/// 2. Résolution des références : variable → nom de paquet,
///    objet → variable, test → objet + état, définition → tests
/// 3. Construction de l'index : nom de paquet → Vec<CveEntry>
async fn parse_oval_file(path: &Path) -> Result<(HashMap<String, Vec<CveEntry>>, usize), ScanError> {
    let content = tokio::fs::read(path)
        .await
        .map_err(|e| ScanError::ParseError(format!("Erreur de lecture du fichier OVAL: {}", e)))?;

    let mut reader = Reader::from_reader(&content[..]);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    // Accumulateurs pour chaque section
    let mut definitions: Vec<OvalDefinitionRaw> = Vec::new();
    let mut tests: HashMap<String, OvalTestRaw> = HashMap::new();
    let mut objects: HashMap<String, OvalObjectRaw> = HashMap::new();
    let mut states: HashMap<String, OvalStateRaw> = HashMap::new();
    let mut variables: HashMap<String, OvalVariable> = HashMap::new();

    let mut current_section = Section::None;

    // État pour le parsing des éléments composites
    let mut current_def: Option<OvalDefinitionRaw> = None;
    let mut current_test: Option<OvalTestRaw> = None;
    let mut current_object: Option<OvalObjectRaw> = None;
    let mut current_state: Option<OvalStateRaw> = None;
    let mut current_var_id: Option<String> = None;
    let mut current_var_values: Vec<String> = Vec::new();
    let mut in_metadata = false;
    let mut in_advisory = false;
    let mut in_criteria = false;

    // Pile de tags pour savoir dans quelle balise on se trouve
    let mut tag_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name().as_ref().to_vec();
                let tag = String::from_utf8_lossy(&local_name).to_string();

                // Empiler le tag
                tag_stack.push(tag.clone());

                // Traiter les attributs
                handle_def_attrs(&e, &tag, &mut current_section, &mut current_def, &mut current_test, &mut current_object, &mut current_state, &mut current_var_id, &mut current_var_values, &mut variables, &mut in_metadata, &mut in_advisory, &mut in_criteria);
            }

            Ok(Event::Empty(e)) => {
                let local_name = e.local_name().as_ref().to_vec();
                let tag = String::from_utf8_lossy(&local_name).to_string();

                // Traiter les attributs (sans empiler de tag)
                handle_def_attrs(&e, &tag, &mut current_section, &mut current_def, &mut current_test, &mut current_object, &mut current_state, &mut current_var_id, &mut current_var_values, &mut variables, &mut in_metadata, &mut in_advisory, &mut in_criteria);
            }

            Ok(Event::End(e)) => {
                let local_name = e.local_name().as_ref().to_vec();
                let tag = String::from_utf8_lossy(&local_name).to_string();

                // Dépiler le tag
                if !tag_stack.is_empty() && tag_stack.last() == Some(&tag) {
                    tag_stack.pop();
                }

                match tag.as_str() {
                    "definitions" => current_section = Section::None,
                    "tests" => current_section = Section::None,
                    "objects" => current_section = Section::None,
                    "states" => current_section = Section::None,
                    "variables" => current_section = Section::None,

                    "definition" => {
                        if let Some(def) = current_def.take() {
                            definitions.push(def);
                        }
                        in_criteria = false;
                    }
                    "metadata" => {
                        in_metadata = false;
                    }
                    "advisory" => {
                        in_advisory = false;
                    }
                    "criteria" => {
                        in_criteria = false;
                    }

                    "dpkginfo_test" => {
                        if let Some(test) = current_test.take() {
                            tests.insert(test.id.clone(), test);
                        }
                    }
                    "dpkginfo_object" => {
                        if let Some(obj) = current_object.take() {
                            objects.insert(obj.id.clone(), obj);
                        }
                    }
                    "dpkginfo_state" => {
                        if let Some(state) = current_state.take() {
                            states.insert(state.id.clone(), state);
                        }
                    }

                    "constant_variable" => {
                        if let Some(id) = current_var_id.take() {
                            let values = std::mem::take(&mut current_var_values);
                            variables.insert(
                                id.clone(),
                                OvalVariable::Constant { id, values },
                            );
                        }
                    }

                    _ => {}
                }
            }

            Ok(Event::Text(e)) => {
                if let Ok(text) = e.unescape() {
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }

                    // Collecter le texte des constant_variable <value>
                    if current_var_id.is_some() {
                        current_var_values.push(text.to_string());
                        continue;
                    }

                    // Collecter les textes dans les métadonnées des définitions
                    if in_metadata {
                        if let Some(parent_tag) = tag_stack.last() {
                            match parent_tag.as_str() {
                                "title" => {
                                    if let Some(ref mut def) = current_def {
                                        if def.title.is_none() {
                                            def.title = Some(text.to_string());
                                        }
                                    }
                                }
                                "description" => {
                                    if let Some(ref mut def) = current_def {
                                        if def.description.is_none() ||
                                           def.description.as_ref().map_or(true, |d| d.is_empty())
                                        {
                                            def.description = Some(text.to_string());
                                        }
                                    }
                                }
                                "severity" => {
                                    if let Some(ref mut def) = current_def {
                                        if def.severity.is_none() {
                                            def.severity = Some(text.to_string());
                                        }
                                    }
                                }
                                "cve" => {
                                    // Fallback : si le CVE ID n'a pas été trouvé via <reference>
                                    if let Some(ref mut def) = current_def {
                                        if def.cve_id.is_none() {
                                            let id = text.to_string();
                                            // Valider que c'est bien un format CVE-XXXX-XXXX
                                            if id.starts_with("CVE-") || id.starts_with("cve-") {
                                                def.cve_id = Some(id.to_uppercase());
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            Ok(Event::CData(e)) => {
                if let Ok(text) = std::str::from_utf8(&e) {
                    let text = text.trim().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    // CData dans les constant_variable <value>
                    if current_var_id.is_some() {
                        current_var_values.push(text);
                        continue;
                    }
                    // CData dans les métadonnées
                    if in_metadata {
                        if let Some(parent_tag) = tag_stack.last() {
                            if parent_tag == "description" {
                                if let Some(ref mut def) = current_def {
                                    if def.description.is_none() ||
                                       def.description.as_ref().map_or(true, |d| d.is_empty())
                                    {
                                        def.description = Some(text);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ScanError::ParseError(format!(
                    "Erreur de parsing XML OVAL: {}",
                    e
                )));
            }
            _ => {}
        }

        buf.clear();
    }

    log::info!(
        "Parsing terminé : {} définitions, {} tests, {} objets, {} états, {} variables",
        definitions.len(),
        tests.len(),
        objects.len(),
        states.len(),
        variables.len()
    );

    // ─── Résolution des références ─────────────────────────────
    //
    // Pour chaque définition, on suit la chaîne :
    //   definition → test_ref → test → object_ref → object → var_ref → variable → package name
    //   definition → test_ref → test → state_ref → state → version fixe

    let mut package_cves: HashMap<String, Vec<CveEntry>> = HashMap::new();
    let mut total_count = 0usize;

    for def in &definitions {
        let Some(ref cve_id) = def.cve_id else {
            continue;
        };

        let severity = parse_severity(def.severity.as_deref());
        let cvss_score = def.cvss_score.unwrap_or(0.0);
        let description = def
            .description
            .clone()
            .unwrap_or_else(|| format!("Vulnérabilité {} non détaillée", cve_id));

        // Résoudre les packages concernés et les versions fixes
        let mut packages: Vec<(String, Option<String>)> = Vec::new();

        for test_ref in &def.test_refs {
            let Some(test) = tests.get(test_ref) else {
                continue;
            };

            let package_names = test
                .object_ref
                .as_ref()
                .and_then(|obj_ref| objects.get(obj_ref))
                .and_then(|obj| obj.var_ref.as_ref())
                .and_then(|var_ref| match variables.get(var_ref) {
                    Some(OvalVariable::Constant { values, .. }) => Some(values.clone()),
                    _ => None,
                })
                .unwrap_or_default();

            let fixed_version = test.state_ref.as_ref().and_then(|sr| {
                states.get(sr).and_then(|s| {
                    if s.operation.as_deref() == Some("less than") {
                        s.version.clone()
                    } else {
                        None
                    }
                })
            });

            for name in &package_names {
                packages.push((name.clone(), fixed_version.clone()));
            }
        }

        if packages.is_empty() {
            continue;
        }

        total_count += 1;

        // Créer une entrée CVE pour chaque paquet
        for (pkg_name, fixed_version) in &packages {
            let entry = CveEntry {
                cve_id: cve_id.clone(),
                severity,
                cvss_score,
                description: description.clone(),
                fixed_version: fixed_version.clone(),
                remediation: fixed_version.as_ref().map(|v| {
                    format!(
                        "Mettez à jour le paquet '{}' vers la version {} (ou ultérieure)",
                        pkg_name, v
                    )
                }),
            };

            package_cves
                .entry(pkg_name.clone())
                .or_default()
                .push(entry);
        }
    }

    log::info!(
        "Index construit : {} paquets avec {} entrées CVE",
        package_cves.len(),
        total_count
    );

    Ok((package_cves, total_count))
}

// ─── Fonction de dispatch des attributs ─────────────────────────────

/// Dispatch les attributs d'une balise XML dans les structures appropriées.
#[allow(clippy::too_many_arguments)]
fn handle_def_attrs(
    e: &quick_xml::events::BytesStart<'_>,
    tag: &str,
    current_section: &mut Section,
    current_def: &mut Option<OvalDefinitionRaw>,
    current_test: &mut Option<OvalTestRaw>,
    current_object: &mut Option<OvalObjectRaw>,
    current_state: &mut Option<OvalStateRaw>,
    current_var_id: &mut Option<String>,
    current_var_values: &mut Vec<String>,
    variables: &mut HashMap<String, OvalVariable>,
    in_metadata: &mut bool,
    in_advisory: &mut bool,
    in_criteria: &mut bool,
) {
    match tag {
        // Sections
        "definitions" => *current_section = Section::Definitions,
        "tests" => *current_section = Section::Tests,
        "objects" => *current_section = Section::Objects,
        "states" => *current_section = Section::States,
        "variables" => *current_section = Section::Variables,

        // Definition
        "definition" => {
            if matches!(current_section, Section::Definitions) {
                if let Some(id) = get_attr(e, "id") {
                    let class = get_attr(e, "class").unwrap_or_default();
                    if class == "vulnerability" {
                        *current_def = Some(OvalDefinitionRaw {
                            id,
                            ..Default::default()
                        });
                    }
                }
            }
        }
        "metadata" => {
            *in_metadata = true;
        }
        "advisory" => {
            if *in_metadata {
                *in_advisory = true;
            }
        }
        "reference" => {
            if *in_metadata {
                if let Some(source) = get_attr(e, "source") {
                    if source == "CVE" {
                        if let Some(ref_id) = get_attr(e, "ref_id") {
                            if let Some(ref mut def) = current_def {
                                def.cve_id = Some(ref_id);
                            }
                        }
                    }
                }
            }
        }
        "cve" => {
            if *in_advisory {
                if let Some(priority) = get_attr(e, "priority") {
                    if let Some(ref mut def) = current_def {
                        if def.severity.is_none() {
                            def.severity = Some(priority);
                        }
                    }
                }
                if let Some(score_str) = get_attr(e, "cvss_score") {
                    if let Ok(score) = score_str.parse::<f32>() {
                        if let Some(ref mut def) = current_def {
                            def.cvss_score = Some(score);
                        }
                    }
                }
            }
        }
        "criteria" => {
            if matches!(current_section, Section::Definitions) {
                *in_criteria = true;
            }
        }
        "criterion" => {
            if *in_criteria {
                if let Some(test_ref) = get_attr(e, "test_ref") {
                    if let Some(ref mut def) = current_def {
                        def.test_refs.push(test_ref);
                    }
                }
            }
        }

        // Test
        "dpkginfo_test" => {
            if matches!(current_section, Section::Tests) {
                if let Some(id) = get_attr(e, "id") {
                    *current_test = Some(OvalTestRaw {
                        id,
                        ..Default::default()
                    });
                }
            }
        }
        "object" => {
            if let Some(ref mut test) = current_test {
                if let Some(obj_ref) = get_attr(e, "object_ref") {
                    test.object_ref = Some(obj_ref);
                }
            }
            if let Some(ref mut obj) = current_object {
                if let Some(var_ref) = get_attr(e, "var_ref") {
                    obj.var_ref = Some(var_ref);
                }
            }
        }
        "state" => {
            if let Some(ref mut test) = current_test {
                if let Some(state_ref) = get_attr(e, "state_ref") {
                    test.state_ref = Some(state_ref);
                }
            }
        }

        // Object
        "dpkginfo_object" => {
            if matches!(current_section, Section::Objects) {
                if let Some(id) = get_attr(e, "id") {
                    *current_object = Some(OvalObjectRaw {
                        id,
                        ..Default::default()
                    });
                }
            }
        }

        // State
        "dpkginfo_state" => {
            if matches!(current_section, Section::States) {
                if let Some(id) = get_attr(e, "id") {
                    *current_state = Some(OvalStateRaw {
                        id,
                        ..Default::default()
                    });
                }
            }
        }
        "evr" => {
            if let Some(ref mut state) = current_state {
                if let Some(op) = get_attr(e, "operation") {
                    state.operation = Some(op);
                }
            }
        }

        // Variables
        "constant_variable" => {
            if matches!(current_section, Section::Variables) {
                if let Some(id) = get_attr(e, "id") {
                    *current_var_id = Some(id);
                    current_var_values.clear();
                }
            }
        }
        "local_variable" => {
            if matches!(current_section, Section::Variables) {
                if let Some(id) = get_attr(e, "id") {
                    variables.insert(id.clone(), OvalVariable::Local { id });
                }
            }
        }

        _ => {}
    }
}

// ─── Fonctions utilitaires ─────────────────────────────────────────

/// Extrait la valeur d'un attribut XML (retourne une chaîne possédée).
fn get_attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.local_name().as_ref() == name.as_bytes())
        .and_then(|a| a.unescape_value().ok())
        .map(|s| s.to_string())
}

/// Convertit une chaîne de sévérité OVAL/Ubuntu en `Severity`.
fn parse_severity(s: Option<&str>) -> Severity {
    match s {
        Some(s) => match s.to_lowercase().as_str() {
            "critical" | "critique" => Severity::Critical,
            "high" | "élevée" | "elevée" => Severity::High,
            "medium" | "moyenne" => Severity::Medium,
            "low" | "basse" | "negligible" => Severity::Low,
            "info" | "information" | "none" => Severity::Info,
            // Si c'est une chaîne non reconnue, on utilise le score CVSS
            _ => Severity::Info,
        },
        None => Severity::Info,
    }
}

/// Compare deux versions Debian et retourne `Less`, `Equal` ou `Greater`.
///
/// L'algorithme suit le format Debian : `[epoch:]upstream_version[-debian_revision]`
/// avec comparaison des composants dans l'ordre : epoch, upstream, revision.
fn compare_deb_versions(a: &str, b: &str) -> std::cmp::Ordering {
    // Extraire et comparer les epochs
    let (epoch_a, rest_a) = split_epoch(a);
    let (epoch_b, rest_b) = split_epoch(b);

    match epoch_a.cmp(&epoch_b) {
        std::cmp::Ordering::Less => return std::cmp::Ordering::Less,
        std::cmp::Ordering::Greater => return std::cmp::Ordering::Greater,
        std::cmp::Ordering::Equal => {}
    }

    // Comparer le reste (upstream_version[-debian_revision])
    compare_version_strings(rest_a, rest_b)
}

/// Sépare l'epoch d'une version Debian.
/// Retourne (epoch, reste). Si pas d'epoch, retourne (0, version).
fn split_epoch(version: &str) -> (u32, &str) {
    if let Some(pos) = version.find(':') {
        let epoch_str = &version[..pos];
        let rest = &version[pos + 1..];
        match epoch_str.parse::<u32>() {
            Ok(epoch) => (epoch, rest),
            Err(_) => (0, version), // Si l'epoch est invalide, on ignore
        }
    } else {
        (0, version)
    }
}

/// Compare deux chaînes de version en gérant les segments numériques.
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    let a_segments = split_version_segments(a);
    let b_segments = split_version_segments(b);

    let max_len = a_segments.len().max(b_segments.len());

    for i in 0..max_len {
        let a_seg = a_segments.get(i).copied().unwrap_or("");
        let b_seg = b_segments.get(i).copied().unwrap_or("");

        if a_seg.is_empty() && b_seg.is_empty() {
            continue;
        }
        if a_seg.is_empty() {
            return std::cmp::Ordering::Less;
        }
        if b_seg.is_empty() {
            return std::cmp::Ordering::Greater;
        }

        let ordering = compare_segment(a_seg, b_seg);
        if ordering != std::cmp::Ordering::Equal {
            return ordering;
        }
    }

    std::cmp::Ordering::Equal
}

/// Sépare une version Debian/Ubuntu en segments (sépare sur les points,
/// tirets, tildes, etc.).
fn split_version_segments(version: &str) -> Vec<&str> {
    // Sépare sur les points, les tildes, les underscores
    // et les tirets (ces derniers marquent la révision Debian)
    let mut segments = Vec::new();
    let mut start = 0usize;

    for (i, ch) in version.char_indices() {
        match ch {
            '.' | '~' | '_' | '+' => {
                if i > start {
                    segments.push(&version[start..i]);
                }
                segments.push(&version[i..=i]);
                start = i + 1;
            }
            '-' => {
                if i > start {
                    segments.push(&version[start..i]);
                }
                segments.push(&version[i..=i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    if start < version.len() {
        segments.push(&version[start..]);
    }

    segments
}

/// Compare deux segments de version.
fn compare_segment(a: &str, b: &str) -> std::cmp::Ordering {
    // Si les deux sont numériques, comparer numériquement
    if let (Ok(na), Ok(nb)) = (a.parse::<u64>(), b.parse::<u64>()) {
        return na.cmp(&nb);
    }

    // Si l'un est numérique, le numérique est plus grand (selon le standard Debian)
    if a.parse::<u64>().is_ok() {
        return std::cmp::Ordering::Greater;
    }
    if b.parse::<u64>().is_ok() {
        return std::cmp::Ordering::Less;
    }

    // Comparaison lexicale pour les chaînes
    a.cmp(b)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_deb_versions_equal() {
        assert_eq!(compare_deb_versions("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(
            compare_deb_versions("2.4.41-4ubuntu3.13", "2.4.41-4ubuntu3.13"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_compare_deb_versions_less() {
        assert_eq!(
            compare_deb_versions("1.0", "2.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_deb_versions("1.0.0", "1.0.1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_deb_versions("2.4.41-4ubuntu3", "2.4.41-4ubuntu3.13"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_deb_versions_greater() {
        assert_eq!(
            compare_deb_versions("2.0", "1.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_deb_versions("1.0.2", "1.0.1"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_split_version_segments() {
        let segs = split_version_segments("2.4.41-4ubuntu3.13");
        assert!(!segs.is_empty());
        assert!(segs.contains(&"2"));
        assert!(segs.contains(&"41"));
        assert!(segs.contains(&"13"));
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity(Some("critical")), Severity::Critical);
        assert_eq!(parse_severity(Some("high")), Severity::High);
        assert_eq!(parse_severity(Some("medium")), Severity::Medium);
        assert_eq!(parse_severity(Some("low")), Severity::Low);
        assert_eq!(parse_severity(None), Severity::Info);
    }

    #[test]
    fn test_get_attr() {
        let xml = b"<test id='oval:test:1' version='1'/>";
        let mut reader = Reader::from_reader(&xml[..]);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e) | Event::Empty(e)) => {
                    assert_eq!(get_attr(&e, "id"), Some("oval:test:1".to_string()));
                    assert_eq!(get_attr(&e, "version"), Some("1".to_string()));
                    assert_eq!(get_attr(&e, "nonexistent"), None::<String>);
                    break;
                }
                Ok(Event::Eof) => break,
                _ => {}
            }
            buf.clear();
        }
    }
}

