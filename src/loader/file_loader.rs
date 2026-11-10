use std::fs;
use std::path::Path;

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Security::Cryptography::*;

/// 从文件（PEM、DER 或 PFX）加载证书链的 DER 字节序列。
/// 返回的 Vec 中，第一个通常是叶子证书（Leaf Cert）。
pub fn load_certs_from_file(path: &Path, password: Option<&str>) -> Result<Vec<Vec<u8>>, String> {
    let bytes = fs::read(path).map_err(|e| format!("无法读取文件: {}", e))?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if ext == "pfx" || ext == "p12" {
        #[cfg(windows)]
        {
            return load_pfx_windows(&bytes, password.unwrap_or(""));
        }
        #[cfg(not(windows))]
        {
            return Err("PKCS#12 (.pfx/.p12) 解析当前仅在 Windows 平台上通过系统 CryptoAPI 支持".to_string());
        }
    }

    // 尝试以 PEM 解析
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            let certs = parse_pem_certificates(text)?;
            if !certs.is_empty() {
                return Ok(certs);
            }
        }
    }

    // 尝试直接作为单个 DER 格式解析 (X.509 DER 通常以 0x30 开头)
    if bytes.starts_with(&[0x30]) {
        return Ok(vec![bytes]);
    }

    Err("无法识别证书格式，仅支持 PEM (.crt/.pem)、DER (.cer) 以及 PKCS#12 (.pfx/.p12)".to_string())
}

/// 解析文本中的所有 PEM 格式证书
pub fn parse_pem_certificates(pem_text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut certs = Vec::new();
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let mut start_pos = 0;
    while let Some(begin_idx) = pem_text[start_pos..].find(begin_marker) {
        let actual_begin = start_pos + begin_idx + begin_marker.len();
        if let Some(end_idx) = pem_text[actual_begin..].find(end_marker) {
            let actual_end = actual_begin + end_idx;
            let b64_content: String = pem_text[actual_begin..actual_end]
                .lines()
                .map(|line| line.trim())
                .collect();

            let der = base64_decode(&b64_content)
                .map_err(|e| format!("Base64 解码证书失败: {}", e))?;
            certs.push(der);
            start_pos = actual_end + end_marker.len();
        } else {
            break;
        }
    }

    if certs.is_empty() {
        Err("未在文件中找到有效的 '-----BEGIN CERTIFICATE-----' 证书块".to_string())
    } else {
        Ok(certs)
    }
}

/// 简易 Base64 解码器
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("Base64 非法字符: {}", c as char)),
        }
    }

    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return Err("Base64 长度非 4 的倍数".to_string());
    }

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks(4) {
        let b0 = val(chunk[0])?;
        let b1 = val(chunk[1])?;
        let b2 = val(chunk[2])?;
        let b3 = val(chunk[3])?;

        let triple = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn load_pfx_windows(pfx_bytes: &[u8], password: &str) -> Result<Vec<Vec<u8>>, String> {
    unsafe {
        let pfx_blob = CRYPT_INTEGER_BLOB {
            cbData: pfx_bytes.len() as u32,
            pbData: pfx_bytes.as_ptr() as *mut u8,
        };

        let password_wide: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
        let pw_pcwstr = if password.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(password_wide.as_ptr())
        };

        // 导入 PFX 到临时内存证书存储区
        let store_handle = PFXImportCertStore(&pfx_blob, pw_pcwstr, CRYPT_KEY_FLAGS(0))
            .map_err(|e| format!("PFX 导入失败（请检查密码是否正确）: 0x{:08X}", e.code().0))?;

        let mut certs = Vec::new();
        let mut p_cert = CertEnumCertificatesInStore(store_handle, None);
        while !p_cert.is_null() {
            let der_slice = std::slice::from_raw_parts(
                (*p_cert).pbCertEncoded,
                (*p_cert).cbCertEncoded as usize,
            );
            certs.push(der_slice.to_vec());
            p_cert = CertEnumCertificatesInStore(store_handle, Some(p_cert));
        }

        let _ = CertCloseStore(store_handle, 0);

        if certs.is_empty() {
            Err("PFX 文件中未找到有效证书".to_string())
        } else {
            Ok(certs)
        }
    }
}
