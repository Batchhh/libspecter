//! Logging utilities for development builds

pub fn info(msg: &str) {
    eprintln!("[INFO]  {}", msg);
}

pub fn warning(msg: &str) {
    eprintln!("[WARN]  {}", msg);
}

pub fn error(msg: &str) {
    eprintln!("[ERROR] {}", msg);
}

pub fn debug(msg: &str) {
    eprintln!("[DEBUG] {}", msg);
}
