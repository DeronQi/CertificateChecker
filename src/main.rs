#![windows_subsystem = "windows"]

use std::path::Path;
use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use win_cert_checker::ui::app::CertCheckerApp;
use win_cert_checker::{engine, loader};

fn main() -> Result<(), eframe::Error> {
    let args: Vec<String> = std::env::args().collect();

    // 如果指定了命令行参数（例如自动化验收或 CLI 检查），直接执行诊断并输出结果
    if args.len() > 1 && (args.contains(&"--cli".to_string()) || args.contains(&"-c".to_string())) {
        run_cli_mode(&args);
        return Ok(());
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 760.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Windows 域名证书有效性诊断工具"),
        ..Default::default()
    };

    eframe::run_native(
        "Windows 域名证书有效性诊断工具",
        native_options,
        Box::new(|cc| {
            setup_custom_fonts(&cc.egui_ctx);
            Ok(Box::new(CertCheckerApp::default()))
        }),
    )
}

/// 配置 Windows 自带字体（微软雅黑 + Segoe UI 符号），防止字符乱码
fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    let msyh_paths = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyh.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
    ];

    for font_path in msyh_paths {
        if Path::new(font_path).exists() {
            if let Ok(font_bytes) = std::fs::read(font_path) {
                fonts.font_data.insert(
                    "microsoft_yahei".to_owned(),
                    FontData::from_owned(font_bytes),
                );

                fonts
                    .families
                    .entry(FontFamily::Proportional)
                    .or_default()
                    .insert(0, "microsoft_yahei".to_owned());

                fonts
                    .families
                    .entry(FontFamily::Monospace)
                    .or_default()
                    .push("microsoft_yahei".to_owned());
                break;
            }
        }
    }

    // 补充 Segoe UI Emoji 作为符号 fallback
    let emoji_path = "C:\\Windows\\Fonts\\seguiemj.ttf";
    if Path::new(emoji_path).exists() {
        if let Ok(emoji_bytes) = std::fs::read(emoji_path) {
            fonts.font_data.insert(
                "segoe_ui_emoji".to_owned(),
                FontData::from_owned(emoji_bytes),
            );
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .push("segoe_ui_emoji".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("segoe_ui_emoji".to_owned());
        }
    }

    ctx.set_fonts(fonts);
}

fn run_cli_mode(args: &[String]) {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }

    println!("=== Windows 证书检查工具 CLI 模式 ===");
    let mut file_path = None;
    let mut target_domain = "api.example.com".to_string();
    let mut password = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    file_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--domain" | "-d" => {
                if i + 1 < args.len() {
                    target_domain = args[i + 1].clone();
                    i += 1;
                }
            }
            "--password" | "-p" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let file_path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("错误: 未提供 --file 参数");
            return;
        }
    };

    println!("正在加载证书: {}", file_path);
    println!("待校验目标域名: {}", target_domain);

    match loader::load_certs_from_file(Path::new(&file_path), password.as_deref()) {
        Ok(certs) => {
            if certs.is_empty() {
                eprintln!("错误: 证书文件中未包含证书");
                return;
            }
            match engine::diagnose_certificate(&certs[0], &target_domain, 30, true, None) {
                Ok(report) => {
                    println!("\n诊断完成！综合评定: {:?}", report.overall_status);
                    println!("通过项: {}, 警告项: {}, 失败项: {}",
                        report.pass_count(), report.warn_count(), report.fail_count());
                    for (idx, item) in report.items.iter().enumerate() {
                        println!("\n{}. [{:?}] {} - {}", idx + 1, item.severity, item.category, item.title);
                        println!("   详情: {}", item.detail);
                        if let Some(c) = &item.root_cause {
                            println!("   原因: {}", c);
                        }
                        if let Some(s) = &item.suggestion {
                            println!("   建议: {}", s);
                        }
                        if let Some(cmd) = &item.fix_command {
                            println!("   命令: {}", cmd);
                        }
                    }
                }
                Err(e) => eprintln!("诊断执行失败: {}", e),
            }
        }
        Err(e) => eprintln!("加载证书失败: {}", e),
    }
}
