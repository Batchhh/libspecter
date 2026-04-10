//! Dynamic library image lookup utilities

#[cfg(debug_assertions)]
use crate::utils::logger;
use std::ffi::CStr;

#[cfg(debug_assertions)]
use mach2::dyld::_dyld_get_image_vmaddr_slide;
use mach2::dyld::{_dyld_get_image_header, _dyld_get_image_name, _dyld_image_count};
use thiserror::Error;

#[derive(Error, Debug)]
/// Errors that can occur during image lookup
pub enum ImageError {
    /// The specified image was not found
    #[error("Image not found: {0}")]
    NotFound(String),
}

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;

static IMAGE_CACHE: Lazy<RwLock<HashMap<String, usize>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Retrieves the base address of a loaded image by name
///
/// # Arguments
/// * `image_name` - The name of the image (or a substring of it)
///
/// # Returns
/// * `Result<usize, ImageError>` - The base address of the image or an error
pub fn get_image_base(image_name: &str) -> Result<usize, ImageError> {
    {
        let cache = IMAGE_CACHE.read();
        if let Some(&base) = cache.get(image_name) {
            return Ok(base);
        }
    }

    unsafe {
        let count = _dyld_image_count();

        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }

            let name = CStr::from_ptr(name_ptr).to_string_lossy();
            if name.contains(image_name) {
                let header = _dyld_get_image_header(i);
                #[cfg(debug_assertions)]
                let slide = _dyld_get_image_vmaddr_slide(i);

                #[cfg(debug_assertions)]
                logger::info(&format!(
                    "Found image: {} (Index: {}, Base: {:p}, Slide: {:#x})",
                    name, i, header, slide
                ));

                let base = header as usize;

                IMAGE_CACHE.write().insert(image_name.to_string(), base);

                return Ok(base);
            }
        }
    }

    #[cfg(debug_assertions)]
    logger::warning(&format!("Image not found: {}", image_name));
    Err(ImageError::NotFound(image_name.to_string()))
}

pub struct ImageInfo {
    pub index: u32,
    pub name: String,
    pub base: usize,
}

/// Returns information about all currently loaded images
pub fn get_all_images() -> Vec<ImageInfo> {
    let mut images = Vec::new();
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
            let header = _dyld_get_image_header(i);
            if header.is_null() {
                continue;
            }
            images.push(ImageInfo {
                index: i,
                name,
                base: header as usize,
            });
        }
    }
    images
}

/// Returns the number of currently loaded images
pub fn image_count() -> u32 {
    unsafe { _dyld_image_count() }
}

/// Returns the full path of a loaded image by its dyld index, or None if invalid
pub fn get_image_name(index: u32) -> Option<String> {
    unsafe {
        let count = _dyld_image_count();
        if index >= count {
            return None;
        }
        let name_ptr = _dyld_get_image_name(index);
        if name_ptr.is_null() {
            return None;
        }
        Some(CStr::from_ptr(name_ptr).to_string_lossy().into_owned())
    }
}
