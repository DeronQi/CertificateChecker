use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Pass,
    Warning,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticItem {
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub root_cause: Option<String>,
    pub suggestion: Option<String>,
    pub fix_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub san_list: Vec<String>,
    pub serial_number: String,
    pub thumbprint_sha256: String,
    pub key_algorithm: String,
    pub has_private_key: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    pub target_domain: String,
    pub timestamp: String,
    pub overall_status: Severity,
    pub summary: CertificateSummary,
    pub items: Vec<DiagnosticItem>,
}

impl CheckReport {
    pub fn pass_count(&self) -> usize {
        self.items.iter().filter(|i| i.severity == Severity::Pass).count()
    }

    pub fn warn_count(&self) -> usize {
        self.items.iter().filter(|i| i.severity == Severity::Warning).count()
    }

    pub fn fail_count(&self) -> usize {
        self.items.iter().filter(|i| i.severity == Severity::Failure).count()
    }
}
