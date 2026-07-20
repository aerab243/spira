mod app;

fn main() -> iced::Result {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    log::info!("Démarrage de Spira v{}", spira_core::VERSION);
    app::run()
}
