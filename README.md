# PROFIBUS-DP Analyzer

传统工控产线运维排障工具 — 解析 PROFIBUS-DP 抓包二进制报文日志的 Rust CLI 命令行工具。

## ✨ 功能特性

| 特性 | 说明 |
|------|------|
| 📁 **双数据源** | 本地二进制抓包文件 + 管道实时总线流量流（stdin） |
| 🔍 **帧解析引擎** | 自动拆分 DP 主从通信帧，校验 FCS 和分隔符 |
| 📊 **过程数据映射** | 支持 8 种 PDO 数据类型与业务含义自定义绑定 |
| 🚦 **诊断码解析** | 内置 64+ 条 PROFIBUS 标准诊断码，中文描述 |
| 🔎 **多维度过滤** | 按从站地址 / 报文类型 / 诊断码 / 故障状态筛选 |
| 🖨️ **多格式输出** | 彩色表格 / JSON / JSON 美化 / CSV / 写入文件 |
| 📈 **统计汇总** | 从站 / 服务原语 / 故障 Top 分布报告 |
| 🎯 **嵌入式部署** | 单二进制文件，`opt-level=z` 体积优化，目标 Linux 网关 |

## 📁 源码模块分层

```
src/
├── main.rs                # 程序入口，子命令分派
├── cli.rs                 # 命令行参数解析 (clap)
├── packet_reader.rs       # 二进制报文流读取器，支持文件 & stdin
├── protocol_parser.rs     # PROFIBUS-DP 协议帧解析引擎
├── pdo_converter.rs       # 过程数据 PDO 数值转换器 + 缩放
├── protocol_templates.rs  # 协议字段解析模板 / 从站映射表
└── output.rs              # 控制台 JSON / 表格 / CSV 输出
```

## 🔧 从站模板配置

内置以下典型工控设备 PDO 映射模板（`protocol_templates.rs` 可扩展）：

| 地址 | 设备名称 | 类型 | 厂商 |
|------|----------|------|------|
| 3 | S7-1200_CPU | S7-1200 | Siemens (0x002A) |
| 5 | ET200S_IO | ET200S | Siemens (0x002A) |
| 7 | MM440_VFD | MM440 | Siemens (0x002A) |
| 10 | FESTO_Cylinder | CPX-FB13 | FESTO (0x0076) |

## 🚀 使用示例

```bash
# 1. 生成示例抓包文件
profibus-dp-analyzer generate-sample -f test.bin -n 100

# 2. 表格方式解析抓包（默认）
profibus-dp-analyzer parse -f test.bin

# 3. 仅看故障，JSON 美化输出
profibus-dp-analyzer parse -f test.bin --faults-only --json-pretty

# 4. 过滤从站 3,5,7，带统计汇总，输出 CSV 到文件
profibus-dp-analyzer parse -f test.bin -s 3,5,7 --csv --summary -o report.csv

# 5. 按诊断码 0x0004 (参数化故障) 过滤，详细模式
profibus-dp-analyzer parse -f test.bin -d 0x0004 -v

# 6. 管道输入实时处理
cat /dev/profibus_capture | profibus-dp-analyzer parse --json

# 7. 列出内置从站 PDO 映射模板
profibus-dp-analyzer list-templates

# 8. 查询诊断码含义
profibus-dp-analyzer show-diag -c 0x001A
```

## 🔨 构建与部署

### Windows 开发机（MSVC 工具链）

```powershell
# 需要 Visual Studio Build Tools (含 C++ / MSVC 链接器)
cargo build --release
```

### 嵌入式 Linux 网关部署（x86_64-unknown-linux-gnu / armv7）

```bash
# 方式一：使用交叉编译
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target=x86_64-unknown-linux-gnu

# 方式二：在 Linux 网关原生编译
cargo build --release
strip target/release/profibus-dp-analyzer
# 典型体积：< 2 MB (opt-level=z + LTO + strip)
```

### Release Profile 体积优化

```toml
[profile.release]
opt-level = "z"    # 极限体积优化
lto = true         # 链接期优化
codegen-units = 1  # 单代码生成单元
strip = true       # 去除符号
panic = "abort"    # 取消栈展开
```

## 📦 PROFIBUS-DP 协议帧结构

```
┌──────┬──────┬──────┬──────┬──────┬──────┬─────────┬──────┬──────┐
│ SD   │ LE   │ LEr  │ FC   │ DA   │ SA   │ PDU     │ FCS  │ ED   │
│ 0x10 │ len  │ len  │ 1B   │ 1B   │ 1B   │ n 字节  │ 1B   │ 0x16 │
└──────┴──────┴──────┴──────┴──────┴──────┴─────────┴──────┴──────┘
  起始  长度   重复   控制   目的    源    过程/诊断  校验  结束
       字节   长度   字节   地址    地址    数据区    和    符
```

FCS = SUM(DA, SA, PDU) & 0xFF

## 🧪 测试

```bash
cargo test --lib
```

覆盖内容：
- `packet_reader` 字节序 / seek / peek
- `protocol_parser` 帧构造 / 校验和 / 诊断码
- `pdo_converter` 8 种数据类型提取 + 缩放
- `protocol_templates` 映射查表
- `cli` HEX/DEC 双进制解析
