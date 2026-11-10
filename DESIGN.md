# Windows 域名证书有效性检查桌面工具设计规范 (DESIGN.md)

## 1. 概述与背景

在 Windows Server 生产环境（如 IIS Web 站点、Windows 远程桌面网关、WCF/gRPC 服务、微服务网关等）中，域名证书失效通常会导致服务中断或安全告警。常见的故障原因包括：
- 证书时间过期或尚未生效
- 证书缺少 SAN（使用者备用名称）或通配符范围不匹配（如 `*.sub.domain.com` 与 `domain.com` 混淆）
- 缺少完整的中间证书链（Partial Chain），导致客户端不信任
- 根证书不在 Windows 本地“受信任的根证书颁发机构”中（常见于企业内部私有 CA）
- 证书用途（EKU）未包含“服务器身份验证 (`1.3.6.1.5.5.7.3.1`)”
- 私钥缺失或当前服务运行账号没有私钥读取权限

本工具专为 Windows 服务器环境设计，提供单文件免安装的桌面图形界面（GUI），支持直接读取本地证书文件（PEM/DER/PFX）或一键列出系统证书存储区（`LocalMachine` / `CurrentUser`），对指定目标域名进行全方位有效性体检，并提供直接定位的根本原因分析与一键可复制的修复指引（如 PowerShell / certutil 命令）。

---

## 2. 核心架构与功能模块

```
win-cert-checker-gui
├── 1. Loader (证书加载层)
│   ├── File Loader: PEM (.crt/.cer/.pem), DER (.cer), PKCS#12 (.pfx/.p12 带密码)
│   └── WinStore Loader: 枚举/提取 LocalMachine\My, WebHosting, CurrentUser\My
├── 2. Engine (诊断分析引擎)
│   ├── Time Validity: NotBefore / NotAfter 范围检测与 30 天/7 天临期预警
│   ├── Domain & SAN Match: RFC 6125 规则，支持 dNSName、IPAddress、Wildcard (*.domain.com)
│   ├── Windows Chain & Schannel Policy: 调用 Windows CryptoAPI 真实模拟 Windows 信任判定
│   ├── Key & Algorithm: RSA >= 2048、ECC 曲线检测、弱哈希 (MD5/SHA1) 拦截
│   ├── Key Usage & EKU: 检查 Server Authentication 及签名/加密用法
│   └── Private Key Check: 检查是否具备私钥以及私钥可用性
├── 3. Advisor (诊断建议专家库)
│   ├── Root Cause Analysis: 将抽象错误码翻译为直观原因
│   └── Actionable Advice: 提供修复步骤与 Windows certutil/PowerShell 修复指令
└── 4. UI (桌面交互层)
    ├── 来源配置区 (文件浏览 / 系统存储下拉选择)
    ├── 目标配置区 (目标域名、验证开关)
    ├── 综合状态指示灯 (健康 / 警告 / 致命不合格)
    ├── 诊断结果列表 (可折叠明细、高亮标签、一键复制修复命令)
    └── 报告导出 (复制文本报告、导出 JSON)
```

---

## 3. 诊断规则矩阵与修复建议库

| 检查维度 | 判定状态 | 根因分类 (Root Cause) | 调整与修复建议 (Actionable Advice) |
| :--- | :--- | :--- | :--- |
| **有效期** | ❌ FAIL | `CERT_EXPIRED` (证书已于指定时间过期) | 证书已失效，客户端连接将被拦截。请立即申请新证书并在服务中重新绑定。 |
| | ❌ FAIL | `CERT_NOT_YET_VALID` (证书尚未到生效期) | 证书生效时间晚于系统当前时间。请校准 Windows 系统时间（NTP 同步）或等待证书生效。 |
| | ⚠️ WARN | `EXPIRING_SOON` (证书即将在 N 天内过期) | 剩余有效期小于预警阈值。请提前安排续签流水线。 |
| **域名匹配** | ❌ FAIL | `DOMAIN_MISMATCH` (SAN 中未包含目标域名) | 证书 SAN 列表不包含目标域名，现代 TLS 客户端已弃用仅依靠 CN。建议重新签发证书，在 SAN 中追加对应 FQDN。 |
| | ❌ FAIL | `WILDCARD_MULTI_LEVEL` (通配符无法覆盖多级) | 通配符 `*.example.com` 只能匹配单级（如 `a.example.com`），无法匹配 `a.b.example.com`。建议为多级子域申请专用证书。 |
| **系统信任** | ❌ FAIL | `UNTRUSTED_ROOT` (根证书未受信任) | 根证书未导入本机的“受信任的根证书颁发机构”中。修复命令: `certutil -addstore -f "Root" "C:\path\root.crt"` |
| | ❌ FAIL | `PARTIAL_CHAIN` (证书链不完整，缺少中间证书) | 无法回溯到信任锚点。建议导出包含完整链的 PFX，或导入中间 CA: `certutil -addstore -f "CA" "C:\path\intermediate.crt"` |
| **密钥规范** | ❌ FAIL | `WEAK_KEY_LENGTH` (RSA < 2048 位) | 密钥长度不足以抵御现代破解。请重新生成 2048 位以上 RSA 或使用 ECC (P-256/P-384)。 |
| | ❌ FAIL | `WEAK_SIGNATURE_HASH` (使用 MD5/SHA1 签名) | 弱签名哈希已被 Windows 和现代安全协议阻断。必须要求 CA 使用 SHA-256 重新签发。 |
| **用途约束** | ❌ FAIL | `MISSING_SERVER_AUTH_EKU` (缺少服务器身份验证) | 证书扩展用途缺少 `1.3.6.1.5.5.7.3.1`。此证书不可用于 Web/TLS 监听，请更换符合服务端用途的证书。 |
| **私钥关联** | ⚠️ WARN | `NO_PRIVATE_KEY` (证书没有关联私钥) | 当前证书仅包含公钥。若作为客户端发起验证无妨；若部署于 IIS/服务监听端，则因缺少私钥将无法启动监听。 |

---

## 4. 技术栈实现规范

- **编程语言**: Rust (1.99+)
- **GUI 交互库**: `eframe` / `egui`（零外部 C++ 运行时依赖，纯原生单文件，自适应高 DPI，内置软渲染 Fallback，极适合 Windows Server 远程桌面环境）
- **Windows 底层调用**: `windows-rs` (`Win32_Security_Cryptography`)
- **X.509 规则解析**: `x509-parser` / ASN.1 解构
- **多格式支持**: PEM 解析、PKCS#12 (PFX) 解密
- **交付形态**: 单一独立的绿色版 `win-cert-checker.exe`
- **自动化验收**: 集成测试套件 + 模拟界面操作与诊断输出验证
