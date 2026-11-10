use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::fs;
use std::path::Path;
use time::{Duration, OffsetDateTime};
use win_cert_checker::engine::diagnose_certificate;
use win_cert_checker::loader::load_certs_from_file;
use win_cert_checker::models::Severity;

#[test]
fn test_e2e_certificate_scenarios() {
    let test_dir = Path::new("target/test_certs");
    let _ = fs::create_dir_all(test_dir);

    // ==========================================
    // 场景 1: 完全合规的正常证书
    // ==========================================
    let mut params_valid = CertificateParams::default();
    let mut dn_valid = DistinguishedName::new();
    dn_valid.push(DnType::CommonName, "api.example.com");
    dn_valid.push(DnType::OrganizationName, "Test Valid Org");
    params_valid.distinguished_name = dn_valid;
    params_valid.subject_alt_names = vec![
        SanType::DnsName("api.example.com".try_into().unwrap()),
        SanType::DnsName("www.example.com".try_into().unwrap()),
    ];
    let now = OffsetDateTime::now_utc();
    params_valid.not_before = now - Duration::days(10);
    params_valid.not_after = now + Duration::days(300);

    let key_valid = KeyPair::generate().unwrap();
    let cert_valid = params_valid.self_signed(&key_valid).unwrap();
    let valid_pem = cert_valid.pem();
    let valid_pem_path = test_dir.join("valid_cert.pem");
    fs::write(&valid_pem_path, &valid_pem).unwrap();

    let certs = load_certs_from_file(&valid_pem_path, None).expect("加载正常证书成功");
    assert!(!certs.is_empty());

    // 对合法域名测试静态规则
    let report_valid = diagnose_certificate(&certs[0], "api.example.com", 30, false, Some(true))
        .expect("诊断成功");
    assert_eq!(report_valid.overall_status, Severity::Pass, "正常证书静态规则应全部通过");
    assert_eq!(report_valid.fail_count(), 0);

    // ==========================================
    // 场景 2: 证书已过期
    // ==========================================
    let mut params_expired = CertificateParams::default();
    let mut dn_expired = DistinguishedName::new();
    dn_expired.push(DnType::CommonName, "expired.example.com");
    params_expired.distinguished_name = dn_expired;
    params_expired.subject_alt_names = vec![SanType::DnsName("expired.example.com".try_into().unwrap())];
    params_expired.not_before = now - Duration::days(100);
    params_expired.not_after = now - Duration::days(10); // 10天前已过期

    let key_expired = KeyPair::generate().unwrap();
    let cert_expired = params_expired.self_signed(&key_expired).unwrap();
    let expired_pem_path = test_dir.join("expired_cert.pem");
    fs::write(&expired_pem_path, cert_expired.pem()).unwrap();

    let certs_exp = load_certs_from_file(&expired_pem_path, None).unwrap();
    let report_exp = diagnose_certificate(&certs_exp[0], "expired.example.com", 30, false, None).unwrap();
    assert_eq!(report_exp.overall_status, Severity::Failure);
    let time_item = report_exp.items.iter().find(|i| i.category == "时间有效性").unwrap();
    assert_eq!(time_item.severity, Severity::Failure);
    assert!(time_item.title.contains("已过期失效"));
    assert!(time_item.root_cause.is_some());
    assert!(time_item.suggestion.is_some());

    // ==========================================
    // 场景 3: 域名不匹配 (SAN Mismatch)
    // ==========================================
    let report_mismatch = diagnose_certificate(&certs_exp[0], "unrelated.domain.com", 30, false, None).unwrap();
    let domain_item = report_mismatch.items.iter().find(|i| i.category == "域名匹配 (SAN)").unwrap();
    assert_eq!(domain_item.severity, Severity::Failure);
    assert!(domain_item.title.contains("域名不匹配"));
    assert!(domain_item.root_cause.as_ref().unwrap().contains("不在证书所保护的任何 SAN 列表中"));

    // ==========================================
    // 场景 4: 多级通配符误用 (RFC 6125 规则验证)
    // ==========================================
    let mut params_wild = CertificateParams::default();
    let mut dn_wild = DistinguishedName::new();
    dn_wild.push(DnType::CommonName, "*.company.com");
    params_wild.distinguished_name = dn_wild;
    params_wild.subject_alt_names = vec![SanType::DnsName("*.company.com".try_into().unwrap())];
    params_wild.not_before = now - Duration::days(1);
    params_wild.not_after = now + Duration::days(100);

    let key_wild = KeyPair::generate().unwrap();
    let cert_wild = params_wild.self_signed(&key_wild).unwrap();
    let wild_pem_path = test_dir.join("wildcard_cert.pem");
    fs::write(&wild_pem_path, cert_wild.pem()).unwrap();

    let certs_wild = load_certs_from_file(&wild_pem_path, None).unwrap();

    // 单级子域名: test.company.com 应当匹配成功 PASS
    let report_single = diagnose_certificate(&certs_wild[0], "test.company.com", 30, false, None).unwrap();
    let item_single = report_single.items.iter().find(|i| i.category == "域名匹配 (SAN)").unwrap();
    assert_eq!(item_single.severity, Severity::Pass);

    // 多级子域名: sub.test.company.com 应当判定失败 FAIL 并指出原因
    let report_multi = diagnose_certificate(&certs_wild[0], "sub.test.company.com", 30, false, None).unwrap();
    let item_multi = report_multi.items.iter().find(|i| i.category == "域名匹配 (SAN)").unwrap();
    assert_eq!(item_multi.severity, Severity::Failure);
    assert!(item_multi.root_cause.as_ref().unwrap().contains("只能匹配单级子域名"));
    assert!(item_multi.suggestion.as_ref().unwrap().contains("为该多级子域名专门签发专用证书"));

    // ==========================================
    // 场景 5: Windows 原生信任链校验 (自签名触发不受信根)
    // ==========================================
    #[cfg(windows)]
    {
        let report_chain = diagnose_certificate(&certs[0], "api.example.com", 30, true, None).unwrap();
        let chain_item = report_chain.items.iter().find(|i| i.category == "Windows 信任链").unwrap();
        // 自签名证书在未导入系统信任库时，Windows 必定返回 CERT_E_UNTRUSTEDROOT
        assert_eq!(chain_item.severity, Severity::Failure);
        assert!(chain_item.title.contains("CERT_E_UNTRUSTEDROOT"));
        assert!(chain_item.fix_command.as_ref().unwrap().contains("certutil -addstore -f \"Root\""));
    }

    println!("\n✅ 所有场景自动化测试通过！覆盖：正常证书、过期判定、域名SAN不匹配、多级通配符限制、Windows信任链不受信根捕获及修复建议。");
}
