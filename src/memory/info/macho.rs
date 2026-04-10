//! Mach-O segment and section querying via Darwin APIs

use crate::memory::info::image::{ImageError, get_image_base};
use std::ffi::CString;
use thiserror::Error;

unsafe extern "C" {
    fn getsegmentdata(header: *const u8, segname: *const i8, size: *mut libc::c_ulong)
    -> *const u8;

    fn getsectiondata(
        header: *const u8,
        segname: *const i8,
        sectname: *const i8,
        size: *mut libc::c_ulong,
    ) -> *const u8;
}

#[derive(Error, Debug)]
pub enum MachoError {
    #[error("Image not found: {0}")]
    ImageNotFound(#[from] ImageError),
    #[error("Segment not found: {0}")]
    SegmentNotFound(String),
    #[error("Section not found: {0},{1}")]
    SectionNotFound(String, String),
}

pub struct SegmentData {
    pub start: usize,
    pub end: usize,
    pub size: usize,
}

/// Get a named segment from a loaded image
pub fn get_segment(image_name: &str, seg_name: &str) -> Result<SegmentData, MachoError> {
    let base = get_image_base(image_name)?;
    let header = base as *const u8;
    let c_seg =
        CString::new(seg_name).map_err(|_| MachoError::SegmentNotFound(seg_name.to_string()))?;

    let mut size: libc::c_ulong = 0;
    let ptr = unsafe { getsegmentdata(header, c_seg.as_ptr(), &mut size) };

    if ptr.is_null() {
        return Err(MachoError::SegmentNotFound(seg_name.to_string()));
    }

    let start = ptr as usize;
    let sz = size as usize;
    Ok(SegmentData {
        start,
        end: start + sz,
        size: sz,
    })
}

/// Get a named section within a segment from a loaded image
pub fn get_section(
    image_name: &str,
    seg_name: &str,
    sect_name: &str,
) -> Result<SegmentData, MachoError> {
    let base = get_image_base(image_name)?;
    let header = base as *const u8;
    let c_seg = CString::new(seg_name)
        .map_err(|_| MachoError::SectionNotFound(seg_name.to_string(), sect_name.to_string()))?;
    let c_sect = CString::new(sect_name)
        .map_err(|_| MachoError::SectionNotFound(seg_name.to_string(), sect_name.to_string()))?;

    let mut size: libc::c_ulong = 0;
    let ptr = unsafe { getsectiondata(header, c_seg.as_ptr(), c_sect.as_ptr(), &mut size) };

    if ptr.is_null() {
        return Err(MachoError::SectionNotFound(
            seg_name.to_string(),
            sect_name.to_string(),
        ));
    }

    let start = ptr as usize;
    let sz = size as usize;
    Ok(SegmentData {
        start,
        end: start + sz,
        size: sz,
    })
}
