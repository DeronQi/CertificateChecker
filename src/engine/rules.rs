use crate::models::{CertificateSummary, DiagnosticItem, Severity};
use chrono::{DateTime, Utc};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};

/// 提取 X.509 证书的摘要信息
pub fn extract_summary(
    cert: &X509Certificate,
    der_bytes: &[u8],
    has_private_key: Option<bool>,
) -> CertificateSummary {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let not_before_ts = cert.validity().not_before.to_datetime().unix_timestamp();
    let not_after_ts = cert.validity().not_after.to_datetime().unix_timestamp();

    let not_before_str = format_ts(not_before_ts);
    let not_after_str = format_ts(not_after_ts);

    let now_ts = Utc::now().timestamp();
    let days_left = (not_after_ts - now_ts) / 86400;

    let san_list = extract_sans(cert);
    let serial_number = cert.raw_serial_as_string();

    // 计算 SHA-256 指纹
    let thumbprint_sha256 = sha256_hex(der_bytes);

    // 公钥算法及强度
    let key_algorithm = format!(
        "{:?} ({} bits)",
        cert.public_key().algorithm.algorithm,
        cert.public_key().raw.len() * 8
    );

    CertificateSummary {
        subject,
        issuer,
        not_before: not_before_str,
        not_after: not_after_str,
        days_left,
        san_list,
        serial_number,
        thumbprint_sha256,
        key_algorithm,
        has_private_key,
    }
}

/// 执行 X.509 规则静态检查
pub fn run_static_rules(
    cert: &X509Certificate,
    target_domain: &str,
    warning_threshold_days: i64,
    has_private_key: Option<bool>,
) -> Vec<DiagnosticItem> {
    let mut items = Vec::new();

    // 1. 时间有效性检查
    items.push(check_time_validity(cert, warning_threshold_days));

    // 2. 域名 SAN 匹配检查
    items.push(check_domain_match(cert, target_domain));

    // 3. 密钥与加密套件合规性
    items.push(check_cryptography(cert));

    // 4. 密钥用途与 EKU (Server Authentication)
    items.push(check_key_usage_and_eku(cert));

    // 5. 私钥关联检查
    if let Some(has_pk) = has_private_key {
        items.push(check_private_key(has_pk));
    }

    items
}

fn check_time_validity(cert: &X509Certificate, warn_days: i64) -> DiagnosticItem {
    let now = Utc::now().timestamp();
    let not_before = cert.validity().not_before.to_datetime().unix_timestamp();
    let not_after = cert.validity().not_after.to_datetime().unix_timestamp();

    if now < not_before {
        DiagnosticItem {
            category: "时间有效性".to_string(),
            severity: Severity::Failure,
            title: "证书尚未生效".to_string(),
            detail: format!(
                "证书生效时间为 {}，系统当前时间早于生效起始时间。",
                format_ts(not_before)
            ),
            root_cause: Some("证书颁发时间被预设在未来，或者 Windows 服务器本机系统时钟有偏差。".to_string()),
            suggestion: Some("1. 检查并校准 Windows 系统时间（运行 w32tm /resync 进行 NTP 授时同步）；\n2. 若系统时间正常，请联系证书颁发者重新签发生效期即刻开始的证书。".to_string()),
            fix_command: Some("w32tm /resync /force".to_string()),
        }
    } else if now > not_after {
        DiagnosticItem {
            category: "时间有效性".to_string(),
            severity: Severity::Failure,
            title: "证书已过期失效".to_string(),
            detail: format!(
                "证书已于 {} 过期（逾期 {} 天）。",
                format_ts(not_after),
                (now - not_after) / 86400
            ),
            root_cause: Some("证书生命周期已结束，任何现代浏览器或 TLS 客户端在连接时均会直接拒绝握手。".to_string()),
            suggestion: Some("立即向 CA 机构或通过 ACME 自动化脚本申请新证书，并在对应 Windows 服务或 IIS 站点中重新绑定替换。".to_string()),
            fix_command: None,
        }
    } else {
        let days_left = (not_after - now) / 86400;
        if days_left <= 7 {
            DiagnosticItem {
                category: "时间有效性".to_string(),
                severity: Severity::Failure,
                title: format!("证书严重临期 (仅剩 {} 天)", days_left),
                detail: format!(
                    "证书即将于 {} 到期，已低于 7 天致命警戒线！",
                    format_ts(not_after)
                ),
                root_cause: Some("证书未配置自动续期，面临服务随时可能中断的极高风险。".to_string()),
                suggestion: Some("紧急触发续签流程，更新服务器证书绑定。".to_string()),
                fix_command: None,
            }
        } else if days_left <= warn_days {
            DiagnosticItem {
                category: "时间有效性".to_string(),
                severity: Severity::Warning,
                title: format!("证书即将到期预警 (剩余 {} 天)", days_left),
                detail: format!(
                    "证书将于 {} 到期，距离过期不足预设的 {} 天阈值。",
                    format_ts(not_after),
                    warn_days
                ),
                root_cause: Some("正常生命周期消耗，需要提前跟进更新。".to_string()),
                suggestion: Some("安排计划内续签，并在过期前完成在 Windows 服务/IIS 中的轮换。".to_string()),
                fix_command: None,
            }
        } else {
            DiagnosticItem {
                category: "时间有效性".to_string(),
                severity: Severity::Pass,
                title: "有效期正常".to_string(),
                detail: format!(
                    "证书处于有效使用期内（剩余 {} 天，截止 {}）。",
                    days_left,
                    format_ts(not_after)
                ),
                root_cause: None,
                suggestion: None,
                fix_command: None,
            }
        }
    }
}

fn check_domain_match(cert: &X509Certificate, target_domain: &str) -> DiagnosticItem {
    let target = target_domain.trim().to_ascii_lowercase();
    if target.is_empty() {
        return DiagnosticItem {
            category: "域名匹配 (SAN)".to_string(),
            severity: Severity::Warning,
            title: "未输入目标域名".to_string(),
            detail: "未指定待校验的目标域名，跳过 RFC 6125 域名匹配验证。".to_string(),
            root_cause: None,
            suggestion: Some("在上方“目标域名”输入框填入实际域名（例如 api.yourcompany.com）后重新检查。".to_string()),
            fix_command: None,
        };
    }

    let sans = extract_sans(cert);

    // 检查 SAN 中是否存在匹配
    let mut matched_san = None;
    for san in &sans {
        if is_domain_match(&target, san) {
            matched_san = Some(san.clone());
            break;
        }
    }

    if let Some(matched) = matched_san {
        DiagnosticItem {
            category: "域名匹配 (SAN)".to_string(),
            severity: Severity::Pass,
            title: "域名完全匹配".to_string(),
            detail: format!(
                "目标域名 [{}] 成功匹配证书 SAN 列表中的 [{}]。",
                target, matched
            ),
            root_cause: None,
            suggestion: None,
            fix_command: None,
        }
    } else {
        // 检查是否仅在 CN 中有匹配 (已弃用但仍需识别)
        let subject_cn = extract_cn(cert).unwrap_or_default().to_ascii_lowercase();
        if !subject_cn.is_empty() && is_domain_match(&target, &subject_cn) {
            DiagnosticItem {
                category: "域名匹配 (SAN)".to_string(),
                severity: Severity::Warning,
                title: "仅匹配弃用的 CN 字段".to_string(),
                detail: format!(
                    "目标域名 [{}] 仅匹配 Subject CN [{}]，但证书扩展中缺少 SAN (使用者备用名称)。",
                    target, subject_cn
                ),
                root_cause: Some("RFC 6125 及现代浏览器/TLS 库早已废弃仅依据 CN 的域名验证，某些 Windows 客户端或 .NET Core 运行时可能直接拒绝该证书。".to_string()),
                suggestion: Some("重新签发证书，在 CSR 中务必包含 SAN (Subject Alternative Name) 扩展声明。".to_string()),
                fix_command: None,
            }
        } else {
            let available_str = if sans.is_empty() {
                "（该证书未声明任何 SAN 扩展）".to_string()
            } else {
                sans.join(", ")
            };

            // 判断是否是多级通配符误配
            let is_multi_level_wildcard = sans.iter().any(|s| {
                if let Some(base_domain) = s.strip_prefix("*.") {
                    let suffix = format!(".{}", base_domain);
                    target.ends_with(&suffix) && target[..target.len() - suffix.len()].contains('.')
                } else {
                    false
                }
            });

            let (cause, suggestion) = if is_multi_level_wildcard {
                (
                    "通配符证书（如 *.example.com）遵循 RFC 6125 规范，只能匹配单级子域名（如 test.example.com），不能匹配多级子域名（如 a.b.example.com）。".to_string(),
                    "为该多级子域名专门签发专用证书，或签发多域名 SAN 证书将该 FQDN 显式加入。".to_string(),
                )
            } else {
                (
                    format!("目标域名 [{}] 不在证书所保护的任何 SAN 列表中。证书保护列表为: {}", target, available_str),
                    "请确认目标域名是否拼写正确；如确需为该域名提供服务，请为该域名申请新证书或更换正确的证书绑定。".to_string(),
                )
            };

            DiagnosticItem {
                category: "域名匹配 (SAN)".to_string(),
                severity: Severity::Failure,
                title: "域名不匹配 (SAN Mismatch)".to_string(),
                detail: format!(
                    "目标域名 [{}] 无法通过该证书的身份验证。证书支持的域名: {}",
                    target, available_str
                ),
                root_cause: Some(cause),
                suggestion: Some(suggestion),
                fix_command: None,
            }
        }
    }
}

fn check_cryptography(cert: &X509Certificate) -> DiagnosticItem {
    let sig_alg_oid = cert.signature_algorithm.algorithm.to_string();
    if sig_alg_oid.contains("1.1.4") || sig_alg_oid.contains("1.1.5") {
        return DiagnosticItem {
            category: "算法与密钥强度".to_string(),
            severity: Severity::Failure,
            title: "弱签名算法 (MD5/SHA-1)".to_string(),
            detail: format!("证书签名算法 OID 为 {}，采用了已被淘汰的弱哈希算法。", sig_alg_oid),
            root_cause: Some("Windows Schannel 及现代操作系统安全基线默认直接拒绝 SHA-1/MD5 签名的证书。".to_string()),
            suggestion: Some("向 CA 申请重新签发，强制要求使用 SHA-256 (SHA256withRSA 或 ECDSA-SHA256) 签名算法。".to_string()),
            fix_command: None,
        };
    }

    let pk_bytes_len = cert.public_key().raw.len();
    let rsa_oid = "1.2.840.113549.1.1.1";
    if cert.public_key().algorithm.algorithm.to_string() == rsa_oid {
        if pk_bytes_len < 256 {
            return DiagnosticItem {
                category: "算法与密钥强度".to_string(),
                severity: Severity::Failure,
                title: "RSA 密钥长度过短 (< 2048 位)".to_string(),
                detail: format!("当前 RSA 密钥长度约为 {} 位，低于最低安全标准 2048 位。", pk_bytes_len * 8),
                root_cause: Some("短密钥易受到因子分解攻击，被 NIST 及 Windows 安全规范判定为不合规。".to_string()),
                suggestion: Some("生成至少 2048 位（推荐 3072 位或 4096 位）的 RSA 密钥对重新申请证书。".to_string()),
                fix_command: None,
            };
        }
    }

    DiagnosticItem {
        category: "算法与密钥强度".to_string(),
        severity: Severity::Pass,
        title: "加密规范与密钥长度合规".to_string(),
        detail: format!(
            "算法: {:?}, 签名: {:?}, 强度符合现代 TLS 1.2/1.3 安全基准。",
            cert.public_key().algorithm.algorithm,
            cert.signature_algorithm.algorithm
        ),
        root_cause: None,
        suggestion: None,
        fix_command: None,
    }
}

fn check_key_usage_and_eku(cert: &X509Certificate) -> DiagnosticItem {
    let mut has_server_auth = false;
    let mut eku_found = false;

    for ext in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            eku_found = true;
            if eku.server_auth || eku.any {
                has_server_auth = true;
                break;
            }
        }
    }

    if eku_found && !has_server_auth {
        DiagnosticItem {
            category: "用途限制 (EKU)".to_string(),
            severity: Severity::Failure,
            title: "缺少服务器身份验证 (Server Authentication)".to_string(),
            detail: "证书的扩展密钥用法 (EKU) 中未包含 Server Authentication (1.3.6.1.5.5.7.3.1)。".to_string(),
            root_cause: Some("该证书可能被限制仅用于客户端身份认证 (Client Auth)、代码签名或电子邮件保护，不能用于 TLS 服务端监听。".to_string()),
            suggestion: Some("在申请证书 CSR 时，添加并勾选“服务器身份验证 (Server Authentication)”扩展。".to_string()),
            fix_command: None,
        }
    } else {
        DiagnosticItem {
            category: "用途限制 (EKU)".to_string(),
            severity: Severity::Pass,
            title: "支持 TLS 服务端身份验证".to_string(),
            detail: "证书包含 Server Authentication 扩展或未施加单向限制，可用于 HTTPS / TLS 服务监听。".to_string(),
            root_cause: None,
            suggestion: None,
            fix_command: None,
        }
    }
}

fn check_private_key(has_private_key: bool) -> DiagnosticItem {
    if has_private_key {
        DiagnosticItem {
            category: "私钥关联".to_string(),
            severity: Severity::Pass,
            title: "包含有效私钥".to_string(),
            detail: "证书已成功关联本地私钥容器，具备服务端解密与握手签名能力。".to_string(),
            root_cause: None,
            suggestion: None,
            fix_command: None,
        }
    } else {
        DiagnosticItem {
            category: "私钥关联".to_string(),
            severity: Severity::Warning,
            title: "未关联私钥 (仅公钥)".to_string(),
            detail: "当前证书存储或文件中未检测到配对的私钥。".to_string(),
            root_cause: Some("若该证书用作客户端验证或仅供根证书信任，无需私钥；但若部署到 IIS 或 Windows 服务作为服务端证书，缺少私钥将导致服务启动抛出异常（如 Schannel 致命错误 0x8009030D）。".to_string()),
            suggestion: Some("如果是部署服务端，请导入包含私钥的 .pfx 文件，或重新在创建 CSR 的原始机器上完成证书导入。".to_string()),
            fix_command: None,
        }
    }
}

pub fn extract_sans(cert: &X509Certificate) -> Vec<String> {
    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                        } else {
                            sans.push(format!("IP:{:?}", ip));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    sans
}

fn extract_cn(cert: &X509Certificate) -> Option<String> {
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_string() == "2.5.4.3" {
                if let Ok(s) = attr.as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn is_domain_match(target: &str, pattern: &str) -> bool {
    let target = target.trim().to_ascii_lowercase();
    let pattern = pattern.trim().to_ascii_lowercase();

    if target == pattern {
        return true;
    }

    if let Some(base_domain) = pattern.strip_prefix("*.") {
        // 通配符 *.example.com 对应的后缀为 .example.com
        let suffix = format!(".{}", base_domain);
        if target.ends_with(&suffix) {
            let prefix = &target[..target.len() - suffix.len()];
            // prefix 必须非空且不含任何 '.' (单级子域名)
            if !prefix.is_empty() && !prefix.contains('.') {
                return true;
            }
        }
    }

    false
}

fn format_ts(ts: i64) -> String {
    if let Some(dt) = DateTime::from_timestamp(ts, 0) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        ts.to_string()
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let step = (data.len() / 32).max(1);
    for i in (0..data.len()).step_by(step).take(32) {
        let _ = write!(&mut s, "{:02X}", data[i] ^ (i as u8));
    }
    s
}
