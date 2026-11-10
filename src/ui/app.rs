use std::path::PathBuf;
use std::time::Instant;

use eframe::egui::{self, Color32, Frame, Margin, RichText, Rounding, ScrollArea, Stroke};
use crate::engine::diagnose_certificate;
use crate::loader::{list_windows_store_certs, load_certs_from_file, StoreCertItem, StoreLocation};
use crate::models::{CheckReport, Severity};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertSourceMode {
    WindowsStore,
    LocalFile,
}

pub struct CertCheckerApp {
    pub source_mode: CertSourceMode,

    // 本地文件选项
    pub file_path: String,
    pub file_password: String,

    // Windows 存储区选项
    pub store_location: StoreLocation,
    pub store_name: String,
    pub store_certs: Vec<StoreCertItem>,
    pub selected_store_cert_idx: usize,
    pub store_filter: String,

    // 目标配置
    pub target_domain: String,
    pub warning_threshold_days: i64,
    pub check_windows_chain: bool,

    // 状态与报告
    pub current_report: Option<CheckReport>,
    pub status_message: Option<String>,
    pub copy_feedback: Option<(String, Instant)>,
}

impl Default for CertCheckerApp {
    fn default() -> Self {
        let mut app = Self {
            source_mode: CertSourceMode::WindowsStore,
            file_path: String::new(),
            file_password: String::new(),
            store_location: StoreLocation::LocalMachine,
            store_name: "My".to_string(),
            store_certs: Vec::new(),
            selected_store_cert_idx: 0,
            store_filter: String::new(),
            target_domain: "api.example.com".to_string(),
            warning_threshold_days: 30,
            check_windows_chain: true,
            current_report: None,
            status_message: None,
            copy_feedback: None,
        };
        app.refresh_store_certs();
        app
    }
}

impl CertCheckerApp {
    pub fn refresh_store_certs(&mut self) {
        match list_windows_store_certs(self.store_location.clone(), &self.store_name) {
            Ok(certs) => {
                self.store_certs = certs;
                self.selected_store_cert_idx = 0;
                self.status_message = Some(format!("已成功列出 {} 张系统证书", self.store_certs.len()));
            }
            Err(e) => {
                self.store_certs.clear();
                self.status_message = Some(format!("读取系统证书库失败: {}", e));
            }
        }
    }

    pub fn browse_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("证书文件 (*.crt, *.cer, *.pem, *.pfx, *.p12)", &["crt", "cer", "pem", "pfx", "p12"])
            .add_filter("所有文件 (*.*)", &["*"])
            .pick_file()
        {
            self.file_path = path.to_string_lossy().to_string();
        }
    }

    pub fn open_cert_manager(&self) {
        let tool = match self.store_location {
            StoreLocation::LocalMachine => "certlm.msc",
            StoreLocation::CurrentUser => "certmgr.msc",
        };
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", tool])
            .spawn();
    }

    pub fn run_diagnosis(&mut self) {
        self.status_message = None;

        let (der_bytes, has_pk) = match self.source_mode {
            CertSourceMode::LocalFile => {
                if self.file_path.trim().is_empty() {
                    self.status_message = Some("请先选择本地证书文件！".to_string());
                    return;
                }
                let pw = if self.file_password.is_empty() {
                    None
                } else {
                    Some(self.file_password.as_str())
                };

                match load_certs_from_file(&PathBuf::from(&self.file_path), pw) {
                    Ok(certs) => {
                        if certs.is_empty() {
                            self.status_message = Some("证书文件中没有找到任何证书！".to_string());
                            return;
                        }
                        (certs[0].clone(), None)
                    }
                    Err(e) => {
                        self.status_message = Some(format!("加载证书文件失败: {}", e));
                        return;
                    }
                }
            }
            CertSourceMode::WindowsStore => {
                let filtered = self.get_filtered_cert_indices();
                if filtered.is_empty() {
                    self.status_message = Some("当前存储区未找到证书或无符合筛选条件的证书！".to_string());
                    return;
                }
                let actual_idx = if self.selected_store_cert_idx < filtered.len() {
                    filtered[self.selected_store_cert_idx]
                } else {
                    filtered[0]
                };
                let item = &self.store_certs[actual_idx];
                (item.der_bytes.clone(), Some(item.has_private_key))
            }
        };

        match diagnose_certificate(
            &der_bytes,
            &self.target_domain,
            self.warning_threshold_days,
            self.check_windows_chain,
            has_pk,
        ) {
            Ok(report) => {
                self.current_report = Some(report);
            }
            Err(e) => {
                self.status_message = Some(format!("证书诊断失败: {}", e));
            }
        }
    }

    pub fn get_filtered_cert_indices(&self) -> Vec<usize> {
        let kw = self.store_filter.trim().to_ascii_lowercase();
        if kw.is_empty() {
            (0..self.store_certs.len()).collect()
        } else {
            self.store_certs
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    c.display_name.to_ascii_lowercase().contains(&kw)
                        || c.subject.to_ascii_lowercase().contains(&kw)
                        || c.thumbprint_sha1.to_ascii_lowercase().contains(&kw)
                })
                .map(|(idx, _)| idx)
                .collect()
        }
    }
}

impl eframe::App for CertCheckerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // 顶部固定控制面板（不随日志滚动）
            self.render_header(ui);
            ui.add_space(4.0);

            self.render_source_selector(ui);
            ui.add_space(4.0);

            self.render_target_and_actions(ui);
            ui.add_space(6.0);

            if let Some(msg) = &self.status_message {
                ui.label(RichText::new(msg).color(Color32::from_rgb(255, 140, 0)));
                ui.add_space(4.0);
            }

            // 状态摘要条
            if let Some(report) = &self.current_report {
                self.render_summary_strip(ui, report);
                ui.add_space(4.0);
            }

            // 仅在日志区域展示终端输出与滚动条
            self.render_terminal_logs(ui);
        });
    }
}

impl CertCheckerApp {
    fn render_header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Windows 域名证书有效性诊断工具").strong().size(18.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("打开证书管理器 (certlm.msc)").clicked() {
                    self.open_cert_manager();
                }
            });
        });
        ui.label(
            RichText::new("针对 Windows Server 生产环境（IIS / 服务自建 TLS / Schannel）的域名匹配、系统信任链与合规深度体检。")
                .color(Color32::from_gray(120))
                .size(12.0),
        );
        ui.separator();
    }

    fn render_source_selector(&mut self, ui: &mut egui::Ui) {
        let card_frame = Frame::none()
            .fill(Color32::from_rgb(250, 251, 253))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(218, 222, 228)))
            .rounding(Rounding::same(4.0))
            .inner_margin(Margin::same(10.0));

        card_frame.show(ui, |ui| {
            ui.set_width(ui.available_width());

            ui.label(RichText::new("第一步：选择待检查的证书来源").strong());
            ui.horizontal(|ui| {
                if ui
                    .radio_value(
                        &mut self.source_mode,
                        CertSourceMode::WindowsStore,
                        "Windows 系统证书库",
                    )
                    .clicked()
                {
                    self.refresh_store_certs();
                }
                ui.radio_value(
                    &mut self.source_mode,
                    CertSourceMode::LocalFile,
                    "本地证书文件 (.crt / .pem / .pfx)",
                );
            });

            ui.add_space(4.0);

            match self.source_mode {
                CertSourceMode::WindowsStore => {
                    ui.horizontal(|ui| {
                        ui.label("存储位置:");
                        let prev_loc = self.store_location.clone();
                        egui::ComboBox::from_id_salt("store_loc_combo")
                            .selected_text(match self.store_location {
                                StoreLocation::LocalMachine => "LocalMachine (本地计算机/服务专用)",
                                StoreLocation::CurrentUser => "CurrentUser (当前登录用户)",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.store_location,
                                    StoreLocation::LocalMachine,
                                    "LocalMachine (本地计算机/服务专用)",
                                );
                                ui.selectable_value(
                                    &mut self.store_location,
                                    StoreLocation::CurrentUser,
                                    "CurrentUser (当前登录用户)",
                                );
                            });

                        if prev_loc != self.store_location {
                            self.refresh_store_certs();
                        }

                        ui.add_space(8.0);
                        ui.label("存储区名:");
                        let prev_name = self.store_name.clone();
                        egui::ComboBox::from_id_salt("store_name_combo")
                            .selected_text(&self.store_name)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.store_name, "My".to_string(), "My (个人/服务端)");
                                ui.selectable_value(&mut self.store_name, "WebHosting".to_string(), "WebHosting (Web托管)");
                                ui.selectable_value(&mut self.store_name, "Root".to_string(), "Root (受信任的根)");
                                ui.selectable_value(&mut self.store_name, "CA".to_string(), "CA (中级证书机构)");
                            });

                        if prev_name != self.store_name {
                            self.refresh_store_certs();
                        }

                        if ui.button("刷新列表").clicked() {
                            self.refresh_store_certs();
                        }
                    });

                    // 快速筛选
                    ui.horizontal(|ui| {
                        ui.label("筛选搜索:");
                        let filter_width = (ui.available_width() - 80.0).max(180.0);
                        ui.add(egui::TextEdit::singleline(&mut self.store_filter).desired_width(filter_width));
                    });

                    let filtered_indices = self.get_filtered_cert_indices();
                    if filtered_indices.is_empty() {
                        ui.label(RichText::new("未在此存储区找到证书").italics().color(Color32::GRAY));
                    } else {
                        let selected_label = if self.selected_store_cert_idx < filtered_indices.len() {
                            let actual_idx = filtered_indices[self.selected_store_cert_idx];
                            let c = &self.store_certs[actual_idx];
                            let key_sym = if c.has_private_key { "[私钥]" } else { "[仅公钥]" };
                            format!("{} {} | 到期: {}", key_sym, c.display_name, c.not_after)
                        } else {
                            "请选择证书...".to_string()
                        };

                        let item_labels: Vec<(usize, String)> = filtered_indices
                            .iter()
                            .enumerate()
                            .map(|(combo_idx, &actual_idx)| {
                                let c = &self.store_certs[actual_idx];
                                let key_sym = if c.has_private_key { "[私钥]" } else { "[仅公钥]" };
                                (combo_idx, format!("{} {} | 到期: {}", key_sym, c.display_name, c.not_after))
                            })
                            .collect();

                        let combo_width = (ui.available_width() - 10.0).max(400.0);
                        egui::ComboBox::from_id_salt("cert_picker_combo")
                            .width(combo_width)
                            .selected_text(selected_label)
                            .show_ui(ui, |ui| {
                                for (combo_idx, label) in item_labels {
                                    ui.selectable_value(&mut self.selected_store_cert_idx, combo_idx, label);
                                }
                            });
                    }
                }
                CertSourceMode::LocalFile => {
                    ui.horizontal(|ui| {
                        ui.label("文件路径:");
                        let file_width = (ui.available_width() - 120.0).max(200.0);
                        ui.add(egui::TextEdit::singleline(&mut self.file_path).desired_width(file_width));
                        if ui.button("浏览...").clicked() {
                            self.browse_file();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("PFX 密码 (可选):");
                        ui.add(egui::TextEdit::singleline(&mut self.file_password).password(true).desired_width(200.0));
                        ui.label(RichText::new("如果是带密码的 .pfx/.p12，请在此输入").color(Color32::GRAY));
                    });
                }
            }
        });
    }

    fn render_target_and_actions(&mut self, ui: &mut egui::Ui) {
        let has_report = self.current_report.is_some();
        let mut copy_report_text = None;
        let mut export_json = false;
        let mut clear_logs = false;

        let card_frame = Frame::none()
            .fill(Color32::from_rgb(250, 251, 253))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(218, 222, 228)))
            .rounding(Rounding::same(4.0))
            .inner_margin(Margin::same(10.0));

        card_frame.show(ui, |ui| {
            ui.set_width(ui.available_width());

            ui.label(RichText::new("第二步：配置校验目标与规则").strong());

            ui.horizontal(|ui| {
                ui.label("待校验目标域名:");
                let domain_width = (ui.available_width() - 320.0).max(220.0);
                ui.add(egui::TextEdit::singleline(&mut self.target_domain).desired_width(domain_width).hint_text("例如 api.company.com"));
                ui.label(RichText::new("(将严格依照 RFC 6125 进行 SAN 匹配)").color(Color32::GRAY));
            });

            ui.horizontal(|ui| {
                ui.label("临期预警阈值 (天):");
                ui.add(egui::DragValue::new(&mut self.warning_threshold_days).range(1..=365));

                ui.add_space(16.0);
                ui.checkbox(&mut self.check_windows_chain, "验证 Windows 系统信任链与 Schannel 策略");
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let btn = ui.add_sized(
                    [200.0, 32.0],
                    egui::Button::new(RichText::new("开始全方位体检").size(14.0).strong()),
                );
                if btn.clicked() {
                    self.run_diagnosis();
                }

                if has_report {
                    if ui.button("复制诊断报告").clicked() {
                        if let Some(report) = &self.current_report {
                            copy_report_text = Some(self.generate_plain_report(report));
                        }
                    }

                    if ui.button("导出 JSON").clicked() {
                        export_json = true;
                    }

                    if ui.button("清空结果").clicked() {
                        clear_logs = true;
                    }
                }

                if let Some((msg, inst)) = &self.copy_feedback {
                    if inst.elapsed().as_secs() < 3 {
                        ui.label(RichText::new(msg).color(Color32::from_rgb(0, 180, 0)));
                    }
                }
            });
        });

        if clear_logs {
            self.current_report = None;
        }

        if let Some(text) = copy_report_text {
            ui.output_mut(|o| o.copied_text = text);
            self.copy_feedback = Some(("诊断报告已复制到剪贴板！".to_string(), Instant::now()));
        }

        if export_json {
            if let Some(report) = &self.current_report {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("cert_report.json")
                    .save_file()
                {
                    if let Ok(json) = serde_json::to_string_pretty(report) {
                        let _ = std::fs::write(path, json);
                    }
                }
            }
        }
    }

    fn render_summary_strip(&self, ui: &mut egui::Ui, report: &CheckReport) {
        let (status_text, bg_color, fg_color) = match report.overall_status {
            Severity::Pass => (
                "● 综合评定：证书完全合规，处于健康有效状态",
                Color32::from_rgb(230, 248, 230),
                Color32::from_rgb(0, 120, 0),
            ),
            Severity::Warning => (
                "● 综合评定：存在潜在风险或警告项（如临期/缺少私钥），请关注",
                Color32::from_rgb(255, 248, 220),
                Color32::from_rgb(180, 110, 0),
            ),
            Severity::Failure => (
                "● 综合评定：证书不被接受，存在致命缺陷（无法正常用于 TLS 服务）",
                Color32::from_rgb(255, 230, 230),
                Color32::from_rgb(180, 0, 0),
            ),
        };

        Frame::none()
            .fill(bg_color)
            .rounding(Rounding::same(4.0))
            .inner_margin(Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(status_text).strong().size(13.0).color(fg_color));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "通过: {} | 警告: {} | 不合格: {}",
                                report.pass_count(),
                                report.warn_count(),
                                report.fail_count()
                            ))
                            .color(Color32::DARK_GRAY)
                            .size(12.0),
                        );
                    });
                });
            });
    }

    /// 终端风格日志输出面板（唯一的内部滚动容器）
    fn render_terminal_logs(&mut self, ui: &mut egui::Ui) {
        let terminal_bg = Color32::from_rgb(22, 24, 28);
        let border_color = Color32::from_rgb(55, 60, 70);

        let mut copied_cmd = None;

        ui.label(RichText::new("诊断终端输出 (Terminal Output):").strong().size(13.0));

        // 深色终端外框，填满剩余所有高度
        Frame::none()
            .fill(terminal_bg)
            .stroke(Stroke::new(1.0_f32, border_color))
            .rounding(Rounding::same(4.0))
            .inner_margin(Margin::same(10.0))
            .show(ui, |ui| {
                // 仅在终端内部启用垂直滚动
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                        if let Some(report) = &self.current_report {
                            // 1. 终端头部概览
                            ui.label(
                                RichText::new("--------------------------------------------------------------------------------")
                                    .color(Color32::from_rgb(100, 110, 120))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "[INFO] 检查时间: {} | 目标域名: {}",
                                    report.timestamp, report.target_domain
                                ))
                                .color(Color32::from_rgb(170, 180, 195))
                                .monospace(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "[INFO] 证书主题: {}",
                                    report.summary.subject
                                ))
                                .color(Color32::from_rgb(170, 180, 195))
                                .monospace(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "[INFO] 颁发机构: {}",
                                    report.summary.issuer
                                ))
                                .color(Color32::from_rgb(170, 180, 195))
                                .monospace(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "[INFO] 有效期限: {} 至 {} (剩余 {} 天)",
                                    report.summary.not_before, report.summary.not_after, report.summary.days_left
                                ))
                                .color(Color32::from_rgb(170, 180, 195))
                                .monospace(),
                            );

                            let pk_str = match report.summary.has_private_key {
                                Some(true) => "包含对应私钥",
                                Some(false) => "未关联私钥 (仅公钥)",
                                None => "未知",
                            };
                            ui.label(
                                RichText::new(format!(
                                    "[INFO] 算法强度: {} | 私钥状态: {}",
                                    report.summary.key_algorithm, pk_str
                                ))
                                .color(Color32::from_rgb(170, 180, 195))
                                .monospace(),
                            );

                            let sans = if report.summary.san_list.is_empty() {
                                "(无 SAN)".to_string()
                            } else {
                                report.summary.san_list.join(", ")
                            };
                            ui.label(
                                RichText::new(format!("[INFO] 备用名称 (SAN): {}", sans))
                                    .color(Color32::from_rgb(170, 180, 195))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new(format!("[INFO] SHA-256: {}", report.summary.thumbprint_sha256))
                                    .color(Color32::from_rgb(140, 150, 165))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new("--------------------------------------------------------------------------------")
                                    .color(Color32::from_rgb(100, 110, 120))
                                    .monospace(),
                            );
                            ui.add_space(6.0);

                            // 2. 诊断明细行（简约终端日志流）
                            for (idx, item) in report.items.iter().enumerate() {
                                let (badge, badge_color) = match item.severity {
                                    Severity::Pass => ("[PASS]", Color32::from_rgb(90, 215, 110)),
                                    Severity::Warning => ("[WARN]", Color32::from_rgb(255, 195, 60)),
                                    Severity::Failure => ("[FAIL]", Color32::from_rgb(255, 85, 85)),
                                };

                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(badge).strong().color(badge_color).monospace());
                                    ui.label(
                                        RichText::new(format!("{}. {}: {}", idx + 1, item.category, item.title))
                                            .strong()
                                            .color(Color32::WHITE)
                                            .monospace(),
                                    );
                                });

                                // 详情
                                ui.label(
                                    RichText::new(format!("       详情: {}", item.detail))
                                        .color(Color32::from_rgb(200, 205, 215))
                                        .monospace(),
                                );

                                // 原因 (若有)
                                if let Some(cause) = &item.root_cause {
                                    ui.label(
                                        RichText::new(format!("       原因: {}", cause))
                                            .color(Color32::from_rgb(255, 140, 140))
                                            .monospace(),
                                    );
                                }

                                // 建议 (若有)
                                if let Some(sug) = &item.suggestion {
                                    for line in sug.lines() {
                                        ui.label(
                                            RichText::new(format!("       建议: {}", line))
                                                .color(Color32::from_rgb(140, 190, 255))
                                                .monospace(),
                                        );
                                    }
                                }

                                // 修复命令 (若有)
                                if let Some(cmd) = &item.fix_command {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format!("       命令: {}", cmd))
                                                .color(Color32::from_rgb(255, 220, 120))
                                                .monospace(),
                                        );
                                        if ui.small_button("复制命令").clicked() {
                                            copied_cmd = Some(cmd.clone());
                                        }
                                    });
                                }

                                ui.add_space(6.0);
                            }

                            ui.label(
                                RichText::new("--------------------------------------------------------------------------------")
                                    .color(Color32::from_rgb(100, 110, 120))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "[DONE] 诊断完成 - 通过: {} 项, 警告: {} 项, 失败: {} 项",
                                    report.pass_count(), report.warn_count(), report.fail_count()
                                ))
                                .color(Color32::from_rgb(180, 190, 200))
                                .monospace(),
                            );
                        } else {
                            // 未开始诊断时的终端提示
                            ui.label(
                                RichText::new("[READY] 等待体检任务启动...")
                                    .color(Color32::from_rgb(120, 130, 140))
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new("[TIP] 请在上方选择证书来源、配置待校验目标域名，然后点击“开始全方位体检”。")
                                    .color(Color32::from_rgb(90, 100, 110))
                                    .monospace(),
                            );
                        }
                    });
            });

        if let Some(cmd) = copied_cmd {
            ui.output_mut(|o| o.copied_text = cmd);
            self.copy_feedback = Some(("修复命令已复制！".to_string(), Instant::now()));
        }
    }

    fn generate_plain_report(&self, report: &CheckReport) -> String {
        let mut s = String::new();
        s.push_str("================================================================================\n");
        s.push_str("                   Windows 域名证书有效性检查报告\n");
        s.push_str(&format!(" 检查时间: {}\n", report.timestamp));
        s.push_str(&format!(" 目标域名: {}\n", report.target_domain));
        s.push_str(&format!(" 证书主题: {}\n", report.summary.subject));
        s.push_str(&format!(" 颁发机构: {}\n", report.summary.issuer));
        s.push_str(&format!(" 有效期限: {} 至 {}\n", report.summary.not_before, report.summary.not_after));
        s.push_str(&format!(" 剩余天数: {} 天\n", report.summary.days_left));
        s.push_str(&format!(" SHA256指纹: {}\n", report.summary.thumbprint_sha256));
        s.push_str(&format!(" 综合状态: {:?} (通过: {}, 警告: {}, 失败: {})\n",
            report.overall_status, report.pass_count(), report.warn_count(), report.fail_count()));
        s.push_str("================================================================================\n\n");

        s.push_str("[详细诊断结果]\n");
        for (i, item) in report.items.iter().enumerate() {
            s.push_str(&format!("{}. [{:?}] {} - {}\n", i + 1, item.severity, item.category, item.title));
            s.push_str(&format!("   详情: {}\n", item.detail));
            if let Some(cause) = &item.root_cause {
                s.push_str(&format!("   原因: {}\n", cause));
            }
            if let Some(sug) = &item.suggestion {
                s.push_str(&format!("   建议: {}\n", sug));
            }
            if let Some(cmd) = &item.fix_command {
                s.push_str(&format!("   命令: {}\n", cmd));
            }
            s.push_str("--------------------------------------------------------------------------------\n");
        }
        s
    }
}
