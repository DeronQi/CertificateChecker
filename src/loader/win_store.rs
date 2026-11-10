use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoreLocation {
    LocalMachine,
    CurrentUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreCertItem {
    pub display_name: String,
    pub subject: String,
    pub issuer: String,
    pub thumbprint_sha1: String,
    pub not_after: String,
    pub has_private_key: bool,
    #[serde(skip)]
    pub der_bytes: Vec<u8>,
}

#[cfg(windows)]
pub fn list_windows_store_certs(
    location: StoreLocation,
    store_name: &str,
) -> Result<Vec<StoreCertItem>, String> {
    use windows::Win32::Security::Cryptography::*;

    unsafe {
        // CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16 = 0x10000
        // CERT_SYSTEM_STORE_LOCAL_MACHINE = 2 << 16 = 0x20000
        let loc_flag: u32 = match location {
            StoreLocation::LocalMachine => 0x00020000,
            StoreLocation::CurrentUser => 0x00010000,
        };
        // CERT_STORE_READONLY_FLAG = 0x00008000
        let store_flags = CERT_OPEN_STORE_FLAGS(loc_flag | 0x00008000);

        let store_name_wide: Vec<u16> = store_name.encode_utf16().chain(std::iter::once(0)).collect();
        let h_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            store_flags,
            Some(store_name_wide.as_ptr() as *const _),
        ).map_err(|e| format!("打开 Windows 证书存储区 [{}] 失败: 0x{:08X}", store_name, e.code().0))?;

        let mut items = Vec::new();
        let mut p_cert = CertEnumCertificatesInStore(h_store, None);

        while !p_cert.is_null() {
            let der_slice = std::slice::from_raw_parts(
                (*p_cert).pbCertEncoded,
                (*p_cert).cbCertEncoded as usize,
            );
            let der_bytes = der_slice.to_vec();

            // 1. 获取友好名称 (Friendly Name)
            let mut friendly_name = String::new();
            let mut name_size = 0u32;
            if CertGetCertificateContextProperty(
                p_cert,
                CERT_FRIENDLY_NAME_PROP_ID,
                None,
                &mut name_size,
            ).is_ok() && name_size > 0 {
                let mut buf: Vec<u8> = vec![0; name_size as usize];
                if CertGetCertificateContextProperty(
                    p_cert,
                    CERT_FRIENDLY_NAME_PROP_ID,
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut name_size,
                ).is_ok() {
                    let u16_slice = std::slice::from_raw_parts(
                        buf.as_ptr() as *const u16,
                        (name_size as usize) / 2,
                    );
                    friendly_name = String::from_utf16_lossy(u16_slice)
                        .trim_matches('\0')
                        .to_string();
                }
            }

            // 2. 获取 SHA-1 指纹
            let mut thumbprint = String::new();
            let mut hash_size = 20u32;
            let mut hash_buf = [0u8; 20];
            if CertGetCertificateContextProperty(
                p_cert,
                CERT_SHA1_HASH_PROP_ID,
                Some(hash_buf.as_mut_ptr() as *mut _),
                &mut hash_size,
            ).is_ok() {
                thumbprint = hash_buf.iter().map(|b| format!("{:02X}", b)).collect();
            }

            // 3. 检查是否关联私钥
            let mut key_info_size = 0u32;
            let has_private_key = CertGetCertificateContextProperty(
                p_cert,
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut key_info_size,
            ).is_ok() && key_info_size > 0;

            // 4. 解析 X.509 简要信息 (Subject, Issuer, NotAfter)
            let (subject, issuer, not_after) = match x509_parser::parse_x509_certificate(&der_bytes) {
                Ok((_, cert)) => {
                    let s = cert.subject().to_string();
                    let i = cert.issuer().to_string();
                    let na = cert.validity().not_after.to_string();
                    (s, i, na)
                }
                Err(_) => ("(解析失败)".to_string(), "-".to_string(), "-".to_string()),
            };

            let display_name = if !friendly_name.is_empty() {
                friendly_name
            } else if !subject.is_empty() {
                subject.clone()
            } else {
                format!("Thumbprint: {}", thumbprint)
            };

            items.push(StoreCertItem {
                display_name,
                subject,
                issuer,
                thumbprint_sha1: thumbprint,
                not_after,
                has_private_key,
                der_bytes,
            });

            p_cert = CertEnumCertificatesInStore(h_store, Some(p_cert));
        }

        let _ = CertCloseStore(h_store, 0);
        Ok(items)
    }
}

#[cfg(not(windows))]
pub fn list_windows_store_certs(
    _location: StoreLocation,
    _store_name: &str,
) -> Result<Vec<StoreCertItem>, String> {
    Err("Windows 证书存储区仅在 Windows 操作系统中有效".to_string())
}
