//! Logging via Apple's unified logging system (os_log)
//! Messages appear in Console.app under the "com.specter" subsystem

use std::sync::Once;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        oslog::OsLogger::new("com.specter")
            .level_filter(log::LevelFilter::Debug)
            .init()
            .expect("failed to initialize os_log");
    });
}

pub fn info(msg: &str) {
    ensure_init();
    log::info!(target: "memory", "{}", msg);
}

pub fn warning(msg: &str) {
    ensure_init();
    log::warn!(target: "memory", "{}", msg);
}

pub fn error(msg: &str) {
    ensure_init();
    log::error!(target: "memory", "{}", msg);
}

pub fn debug(msg: &str) {
    ensure_init();
    log::debug!(target: "memory", "{}", msg);
}
