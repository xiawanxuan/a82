use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    JsonPretty,
    Csv,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum FrameTypeFilter {
    All,
    Srd,
    Sda,
    Csf,
    FdlStatus,
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "profibus-dp-analyzer",
    about = "PROFIBUS-DP 抓包二进制报文日志解析工具 - 用于传统工控产线运维排障",
    version,
    author
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    #[command(about = "解析抓包文件并输出结果")]
    Parse(ParseArgs),

    #[command(about = "列出内置的从站设备模板")]
    ListTemplates,

    #[command(about = "显示诊断码帮助信息")]
    ShowDiagHelp(DiagHelpArgs),

    #[command(about = "创建示例抓包文件用于测试")]
    GenerateSample(GenerateSampleArgs),
}

#[derive(Clone, Debug, Parser)]
pub struct ParseArgs {
    #[arg(
        short,
        long,
        help = "输入的二进制抓包文件路径，不指定则从标准输入读取（支持管道）"
    )]
    pub file: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_enum,
        default_value_t = OutputFormat::Table,
        help = "输出格式"
    )]
    pub format: OutputFormat,

    #[arg(
        short = 's',
        long,
        value_delimiter = ',',
        help = "按从站地址过滤，支持逗号分隔多个，例如: -s 3,5,7"
    )]
    pub slave_filter: Vec<u8>,

    #[arg(
        short = 't',
        long,
        value_enum,
        default_value_t = FrameTypeFilter::All,
        help = "按报文类型过滤"
    )]
    pub frame_type: FrameTypeFilter,

    #[arg(
        short = 'd',
        long,
        help = "按故障诊断码过滤，仅显示包含指定诊断码的帧，例如: -d 0x0004 或 -d 4"
    )]
    pub diag_filter: Option<String>,

    #[arg(long, default_value_t = false, help = "仅显示包含总线故障的帧")]
    pub faults_only: bool,

    #[arg(
        short = 'n',
        long,
        help = "限制显示的帧数量，0 表示不限制"
    )]
    pub limit: Option<usize>,

    #[arg(long, default_value_t = false, help = "显示详细的原始字节数据")]
    pub verbose: bool,

    #[arg(long, default_value_t = false, help = "输出统计汇总信息")]
    pub summary: bool,

    #[arg(
        short,
        long,
        help = "将结果写入到指定文件而不是控制台"
    )]
    pub output: Option<PathBuf>,
}

#[derive(Clone, Debug, Parser)]
pub struct DiagHelpArgs {
    #[arg(help = "要查询的诊断码，例如: 0x0004 或 4")]
    pub code: Option<String>,
}

#[derive(Clone, Debug, Parser)]
pub struct GenerateSampleArgs {
    #[arg(
        short,
        long,
        default_value = "sample_profibus_capture.bin",
        help = "输出的示例抓包文件名"
    )]
    pub file: PathBuf,

    #[arg(
        short,
        long,
        default_value_t = 50,
        help = "生成的帧数量"
    )]
    pub frames: usize,
}

impl ParseArgs {
    pub fn diag_code_filter(&self) -> Option<u16> {
        self.diag_filter.as_ref().and_then(|s| parse_hex_or_dec(s))
    }
}

pub fn parse_hex_or_dec(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.to_lowercase().starts_with("0x") {
        u16::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse::<u16>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_or_dec() {
        assert_eq!(parse_hex_or_dec("0x0004"), Some(4));
        assert_eq!(parse_hex_or_dec("0x04"), Some(4));
        assert_eq!(parse_hex_or_dec("4"), Some(4));
        assert_eq!(parse_hex_or_dec("0xFFFF"), Some(0xFFFF));
        assert_eq!(parse_hex_or_dec("65535"), Some(0xFFFF));
        assert_eq!(parse_hex_or_dec("invalid"), None);
        assert_eq!(parse_hex_or_dec("0xGG"), None);
    }

    #[test]
    fn test_output_format_value_enum() {
        let formats = [
            OutputFormat::Table,
            OutputFormat::Json,
            OutputFormat::JsonPretty,
            OutputFormat::Csv,
        ];
        for f in &formats {
            assert!(matches!(f, _));
        }
    }
}
