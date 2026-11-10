use crate::models::{DiagnosticItem, Severity};

#[cfg(windows)]
pub fn verify_windows_chain(leaf_der: &[u8], target_domain: &str) -> Vec<DiagnosticItem> {
    use std::ptr::null_mut;
    use windows::Win32::Security::Cryptography::*;

    let mut items = Vec::new();
    unsafe {
        let p_cert = CertCreateCertificateContext(
            CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
            leaf_der,
        );

        if p_cert.is_null() {
            items.push(DiagnosticItem {
                category: "Windows 信任链".to_string(),
                severity: Severity::Failure,
                title: "Windows 证书上下文创建失败".to_string(),
                detail: "无法将 DER 字节流转换为 Windows CryptoAPI 原生证书结构。".to_string(),
                root_cause: Some("证书文件可能损坏或 ASN.1 编码不完整。".to_string()),
                suggestion: Some("请重新导出完整的证书文件。".to_string()),
                fix_command: None,
            });
            return items;
        }

        // 1. 构建系统证书链 (CertGetCertificateChain)
        let mut chain_para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };

        let mut p_chain_context: *mut CERT_CHAIN_CONTEXT = null_mut();
        let chain_result = CertGetCertificateChain(
            None,
            p_cert,
            None,
            None,
            &mut chain_para,
            0,
            None,
            &mut p_chain_context,
        );

        if chain_result.is_err() || p_chain_context.is_null() {
            let _ = CertFreeCertificateContext(Some(p_cert));
            items.push(DiagnosticItem {
                category: "Windows 信任链".to_string(),
                severity: Severity::Failure,
                title: "构建系统证书链失败".to_string(),
                detail: "Windows 引擎无法构建该证书的层级关系。".to_string(),
                root_cause: Some("Windows CryptoAPI 内部错误。".to_string()),
                suggestion: None,
                fix_command: None,
            });
            return items;
        }

        // 2. 使用 CERT_CHAIN_POLICY_SSL 策略做系统级模拟校验
        let server_name_wide: Vec<u16> = if !target_domain.trim().is_empty() {
            target_domain.trim().encode_utf16().chain(std::iter::once(0)).collect()
        } else {
            Vec::new()
        };

        let mut https_policy_data = HTTPSPolicyCallbackData {
            Anonymous: HTTPSPolicyCallbackData_0 {
                cbStruct: std::mem::size_of::<HTTPSPolicyCallbackData>() as u32,
            },
            dwAuthType: AUTHTYPE_SERVER,
            fdwChecks: 0,
            pwszServerName: if server_name_wide.is_empty() {
                windows::core::PWSTR::null()
            } else {
                windows::core::PWSTR(server_name_wide.as_ptr() as *mut u16)
            },
        };

        let policy_para = CERT_CHAIN_POLICY_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
            dwFlags: CERT_CHAIN_POLICY_FLAGS(0),
            pvExtraPolicyPara: &mut https_policy_data as *mut _ as *mut _,
        };

        let mut policy_status = CERT_CHAIN_POLICY_STATUS {
            cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
            ..Default::default()
        };

        let _ = CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            p_chain_context,
            &policy_para,
            &mut policy_status,
        );

        let err_code = policy_status.dwError;

        // 根据 Windows 状态码给出专业诊断
        match err_code {
            0 => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Pass,
                    title: "通过 Windows 系统信任链校验 (Schannel 合规)".to_string(),
                    detail: "该证书与本机的 Windows 信任存储区完全吻合，可被 IIS、.NET、WinHTTP 等无缝接受。".to_string(),
                    root_cause: None,
                    suggestion: None,
                    fix_command: None,
                });
            }
            // CERT_E_UNTRUSTEDROOT: 0x800B0109
            0x800B0109 => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "根证书不受信 (CERT_E_UNTRUSTEDROOT - 0x800B0109)".to_string(),
                    detail: "证书的颁发机构根 CA 未在本地 Windows 系统的“受信任的根证书颁发机构”中注册。".to_string(),
                    root_cause: Some("这是私有 CA 或企业内部自签名根证书最常见的报错。Windows 默认不信任未经导入的私有根证书。".to_string()),
                    suggestion: Some("1. 取得企业内部根证书 root.crt；\n2. 以管理员权限运行导入命令，将其加入 LocalMachine 受信任根证书列表。".to_string()),
                    fix_command: Some("certutil -addstore -f \"Root\" \"C:\\path\\to\\root.crt\"".to_string()),
                });
            }
            // CERT_E_CHAINING: 0x800B010A
            0x800B010A => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "证书链中断/缺失中间证书 (CERT_E_CHAINING - 0x800B010A)".to_string(),
                    detail: "Windows 无法通过已有的本地证书库推导至根证书，证书链在中间断开。".to_string(),
                    root_cause: Some("未导入 Intermediate CA（中级 CA），或者向 Windows/IIS 提供的是不包含完整链（Full Chain）的叶子证书。".to_string()),
                    suggestion: Some("1. 重新打包包含完整证书链的 PFX 文件；\n2. 或者将中级证书导入 Windows 的“中级证书颁发机构”存储区。".to_string()),
                    fix_command: Some("certutil -addstore -f \"CA\" \"C:\\path\\to\\intermediate.crt\"".to_string()),
                });
            }
            // CERT_E_CN_NO_MATCH: 0x800B010F
            0x800B010F => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "Windows 判定域名不匹配 (CERT_E_CN_NO_MATCH - 0x800B010F)".to_string(),
                    detail: format!("Windows Schannel 检查发现目标域名 [{}] 与证书的 SAN / CN 不相符。", target_domain),
                    root_cause: Some("Windows SSL 策略拒绝了非匹配域名的证书绑定。".to_string()),
                    suggestion: Some("核实域名拼写，或向 CA 申请包含该域名或单级通配符的证书。".to_string()),
                    fix_command: None,
                });
            }
            // CERT_E_EXPIRED: 0x800B0101
            0x800B0101 => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "Windows 判定证书已过期 (CERT_E_EXPIRED - 0x800B0101)".to_string(),
                    detail: "Windows CryptoAPI 时间校验判定该证书已不在有效期内。".to_string(),
                    root_cause: Some("证书已过期，Windows 驱动层将直接中断 SSL/TLS 握手。".to_string()),
                    suggestion: Some("立即申请新证书并在服务或 IIS 中替换。".to_string()),
                    fix_command: None,
                });
            }
            // CERT_E_WRONG_USAGE: 0x800B0110
            0x800B0110 => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "证书用途不符合 SSL 服务端规范 (CERT_E_WRONG_USAGE - 0x800B0110)".to_string(),
                    detail: "该证书无法满足 Windows SSL 策略要求的用途限制。".to_string(),
                    root_cause: Some("证书未启用 Server Authentication EKU。".to_string()),
                    suggestion: Some("申请具备“服务器身份验证”用途的正式证书。".to_string()),
                    fix_command: None,
                });
            }
            // CRYPT_E_REVOKED: 0x80092010
            0x80092010 => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: "证书已被吊销 (CRYPT_E_REVOKED - 0x80092010)".to_string(),
                    detail: "Windows 收到 CRL 或 OCSP 响应，表明该证书已被颁发机构作废。".to_string(),
                    root_cause: Some("证书私钥可能已被标记泄露或管理者主动作废。".to_string()),
                    suggestion: Some("立即停止使用此证书，废弃旧私钥，重新申请新证书。".to_string()),
                    fix_command: None,
                });
            }
            other => {
                items.push(DiagnosticItem {
                    category: "Windows 信任链".to_string(),
                    severity: Severity::Failure,
                    title: format!("Windows 策略拒绝 (错误代码 0x{:08X})", other),
                    detail: format!("Windows CryptoAPI 返回了未通过的代码: 0x{:08X}", other),
                    root_cause: Some("Windows 安全策略拦截。".to_string()),
                    suggestion: Some("请结合 Windows 事件查看器 (Event Viewer) -> 系统日志 -> Schannel 事件进一步定位。".to_string()),
                    fix_command: None,
                });
            }
        }

        CertFreeCertificateChain(p_chain_context);
        let _ = CertFreeCertificateContext(Some(p_cert));
    }

    items
}

#[cfg(not(windows))]
pub fn verify_windows_chain(_leaf_der: &[u8], _target_domain: &str) -> Vec<DiagnosticItem> {
    vec![DiagnosticItem {
        category: "Windows 信任链".to_string(),
        severity: Severity::Warning,
        title: "跳过 Windows 原生信任链校验".to_string(),
        detail: "当前非 Windows 运行环境，无法调用 Windows CryptoAPI。".to_string(),
        root_cause: None,
        suggestion: None,
        fix_command: None,
    }]
}
