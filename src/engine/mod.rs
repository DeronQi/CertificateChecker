pub mod rules;
pub mod win_chain;

use crate::models::{CheckReport, DiagnosticItem, Severity};
use chrono::Utc;
use rules::{extract_summary, run_static_rules};
use win_chain::verify_windows_chain;

/// 综合诊断函数：输入 DER 字节、目标域名、阈值、是否启用系统链
pub fn diagnose_certificate(
    der_bytes: &[u8],
    target_domain: &str,
    warning_threshold_days: i64,
    check_windows_chain: bool,
    has_private_key: Option<bool>,
) -> Result<CheckReport, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der_bytes)
        .map_err(|e| format!("X.509 ASN.1 解析失败: {:?}", e))?;

    let summary = extract_summary(&cert, der_bytes, has_private_key);

    let mut items: Vec<DiagnosticItem> = Vec::new();

    // 1. 静态规则诊断
    let static_items = run_static_rules(&cert, target_domain, warning_threshold_days, has_private_key);
    items.extend(static_items);

    // 2. Windows 系统信任链与 Schannel 策略诊断
    if check_windows_chain {
        let chain_items = verify_windows_chain(der_bytes, target_domain);
        items.extend(chain_items);
    }

    // 计算综合状态
    let mut overall_status = Severity::Pass;
    for item in &items {
        if item.severity == Severity::Failure {
            overall_status = Severity::Failure;
            break;
        } else if item.severity == Severity::Warning && overall_status != Severity::Failure {
            overall_status = Severity::Warning;
        }
    }

    Ok(CheckReport {
        target_domain: target_domain.to_string(),
        timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        overall_status,
        summary,
        items,
    })
}
