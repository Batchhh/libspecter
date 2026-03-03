//! Project configuration

use once_cell::sync::Lazy;
use parking_lot::RwLock;

static TARGET_IMAGE_NAME: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));

/// Returns the currently configured target image name, or `None` if `mem_init` has not been called.
pub fn get_target_image_name() -> Option<String> {
    TARGET_IMAGE_NAME.read().clone()
}

/// Sets the target image name (called by `mem_init` via the FFI layer).
pub fn set_target_image_name(name: &str) {
    *TARGET_IMAGE_NAME.write() = Some(name.to_string());
}
