#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Globalization::{GetACP, GetOEMCP, MultiByteToWideChar};

pub(crate) fn decode_process_output(program: &str, bytes: &[u8]) -> String {
    #[cfg(not(windows))]
    let _ = program;

    if bytes.is_empty() {
        return String::new();
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }

    #[cfg(windows)]
    if let Some(text) = decode_windows_process_output(program, bytes) {
        return text;
    }

    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn decode_windows_process_output(program: &str, bytes: &[u8]) -> Option<String> {
    decode_windows_process_output_with_code_pages(program, bytes, unsafe { GetACP() }, unsafe {
        GetOEMCP()
    })
}

#[cfg(windows)]
fn decode_windows_process_output_with_code_pages(
    program: &str,
    bytes: &[u8],
    ansi_code_page: u32,
    oem_code_page: u32,
) -> Option<String> {
    if let Some(text) = decode_utf16le_if_likely(bytes) {
        return Some(text);
    }

    let program_name = normalize_program_name(program);
    let code_pages = match program_name.as_deref() {
        Some("cmd") => dedupe_code_pages([oem_code_page, ansi_code_page]),
        Some("powershell" | "pwsh") => dedupe_code_pages([ansi_code_page, oem_code_page]),
        _ => dedupe_code_pages([ansi_code_page, oem_code_page]),
    };
    for code_page in code_pages {
        if let Some(text) = decode_windows_code_page(bytes, code_page) {
            return Some(text);
        }
    }
    None
}

#[cfg(windows)]
fn normalize_program_name(program: &str) -> Option<String> {
    let file_name = Path::new(program).file_name()?.to_string_lossy();
    let trimmed = file_name.strip_suffix(".exe").unwrap_or(&file_name);
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(windows)]
fn dedupe_code_pages(candidates: [u32; 2]) -> Vec<u32> {
    let mut pages = Vec::new();
    for page in candidates {
        if page != 0 && !pages.contains(&page) {
            pages.push(page);
        }
    }
    pages
}

#[cfg(windows)]
fn decode_utf16le_if_likely(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16le(bytes, 2);
    }

    let mut pairs = 0usize;
    let mut zero_high_bytes = 0usize;
    for chunk in bytes.chunks_exact(2).take(64) {
        pairs += 1;
        if chunk[1] == 0 {
            zero_high_bytes += 1;
        }
    }
    if pairs < 4 {
        return None;
    }
    if zero_high_bytes * 5 < pairs {
        return None;
    }
    decode_utf16le(bytes, 0)
}

#[cfg(windows)]
fn decode_utf16le(bytes: &[u8], start: usize) -> Option<String> {
    let units = bytes
        .get(start..)?
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(windows)]
fn decode_windows_code_page(bytes: &[u8], code_page: u32) -> Option<String> {
    let byte_len = i32::try_from(bytes.len()).ok()?;
    let required_len = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            byte_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if required_len <= 0 {
        return None;
    }

    let mut wide = vec![0u16; required_len as usize];
    let written_len = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            byte_len,
            wide.as_mut_ptr(),
            required_len,
        )
    };
    if written_len <= 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&wide[..written_len as usize]))
}

#[cfg(test)]
mod tests {
    use super::decode_process_output;
    #[cfg(windows)]
    use super::{decode_utf16le_if_likely, decode_windows_process_output_with_code_pages};

    #[test]
    fn decode_process_output_preserves_utf8() {
        assert_eq!(
            decode_process_output("cmd", "中文输出\n".as_bytes()),
            "中文输出\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn decode_windows_process_output_falls_back_to_ansi_code_page() {
        let Some(decoded) = decode_windows_process_output_with_code_pages(
            "uv",
            &[0xCE, 0xC4, 0xBC, 0xFE],
            936,
            437,
        ) else {
            panic!("decode ansi output");
        };

        assert_eq!(decoded, "文件");
    }

    #[cfg(windows)]
    #[test]
    fn decode_utf16le_if_likely_accepts_cmd_u_output() {
        let Some(decoded) =
            decode_utf16le_if_likely(&[0xFF, 0xFE, 0x87, 0x65, 0xF6, 0x4E, 0x0D, 0x00, 0x0A, 0x00])
        else {
            panic!("utf16");
        };

        assert_eq!(decoded, "文件\r\n");
    }
}
