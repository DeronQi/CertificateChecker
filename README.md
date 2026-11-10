# Windows 域名证书有效性诊断工具 (win-cert-checker)

一个轻量、高效、免安装的 Windows 域名证书全维度有效性检查与故障排查工具。专为 Windows Server 生产环境（IIS / 独立 TLS 微服务 / Schannel 通信）打造。

---

## 核心特性

- **绿色单文件运行**：编译后仅约 5MB，纯原生 Native 窗口，零外部运行时依赖（无需 WebView2、无需 VC++ 运行库）。
- **双来源接入**：
  - **Windows 系统证书存储区**：动态枚举并读取 `LocalMachine` / `CurrentUser` 下的 `My`（个人）、`WebHosting`（Web托管）、`Root`、`CA` 等存储区，自动检测私钥关联状态。
  - **本地文件加载**：支持 PEM (`.crt`/`.pem`)、DER (`.cer`) 以及 PKCS#12 (`.pfx`/`.p12`，支持口令保护)。
- **全方位规则诊断矩阵**：
  - **时间有效性**：精确识别过期（`CERT_EXPIRED`）、尚未生效及 30/7 天临期预警，给出 NTP 授时校准指引。
  - **域名 SAN 匹配**：严格遵循 RFC 6125 规范，智能拦截多级通配符误配（如 `*.domain.com` 试图匹配 `a.b.domain.com`）。
  - **Windows 原生 Schannel 信任链真实验证**：调用系统 CryptoAPI（`CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL)`），真实模拟 Windows 系统对证书的接受情况，捕获 `0x800B0109`（根证书不受信）等错误并生成一键修复命令。
  - **密钥安全与用途**：检测 RSA 位长（>= 2048）、弱哈希算法（拦截 MD5/SHA-1）、检查 `Server Authentication` EKU。
- **极简终端输出面板**：深色控制台终端日志流，规整清晰，滚动条独立生效，顶部配置栏稳固置顶。
- **一键快捷运维**：集成一键启动 Windows 证书管理器 (`certlm.msc`)、一键复制格式化报告与修复命令、导出 JSON 诊断结果。

---

## 构建与运行

### 环境准备
- Rust 1.75+ (推荐最新稳定版)
- Windows 10 / 11 / Windows Server 2016+

### 编译 Release 版本
```bash
cargo build --release
```
编译产物位于 `target/release/win_cert_checker.exe`，可直接复制到任意 Windows 服务器上双击运行。

### 命令行诊断模式 (CLI)
工具亦支持在终端中静默执行，便于集成至 CI/CD 流水线或监控探针：
```bash
win_cert_checker.exe --cli --file "C:\certs\server.crt" --domain "api.example.com"
```

---

## 开源许可

[MIT License](LICENSE)
