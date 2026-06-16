use crate::cli::{FilterSpec, FilterWarning, FrameTypeFilter, OutputFormat, format_filter_warning};
use crate::pdo_converter::{ConvertedPdoFrame, ConvertedValue};
use crate::protocol_parser::{FrameType, ParsedFrame};
use crate::protocol_templates::ProtocolTemplates;
use colored::*;
use comfy_table::{Cell, ContentArrangement, Table};
use serde::Serialize;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct StatisticsSummary {
    pub total_frames: usize,
    pub filtered_frames: usize,
    pub faults_count: usize,
    pub unique_slaves: usize,
    pub slaves: Vec<(u8, String, usize)>,
    pub frame_type_counts: HashMap<String, usize>,
    pub service_counts: HashMap<String, usize>,
    pub diagnostic_counts: HashMap<String, usize>,
}

fn frame_type_matches(filter: FrameTypeFilter, actual: FrameType) -> bool {
    match filter {
        FrameTypeFilter::All => true,
        FrameTypeFilter::Srd => matches!(
            actual,
            FrameType::Srd | FrameType::SrdHigh | FrameType::SrdLow
        ),
        FrameTypeFilter::Sda => matches!(actual, FrameType::Sda),
        FrameTypeFilter::Csf => matches!(actual, FrameType::Csf),
        FrameTypeFilter::FdlStatus => matches!(actual, FrameType::FdlStatus),
    }
}

fn diag_condition_satisfied(frame: &ParsedFrame, spec: &FilterSpec) -> bool {
    if !spec.faults_only && spec.diag_codes.is_empty() {
        return true;
    }

    let has_explicit_diag = !spec.diag_codes.is_empty();

    if spec.faults_only {
        if !frame.bus_fault {
            return false;
        }
        if !has_explicit_diag {
            return true;
        }
    }

    if has_explicit_diag {
        let frame_has_any_target = frame
            .diagnostic_data
            .iter()
            .any(|d| spec.diag_codes.contains(&d.code));
        if frame_has_any_target {
            return true;
        }
        if !spec.faults_only && frame.diagnostic_data.is_empty() {
            return true;
        }
        return false;
    }

    true
}

pub fn filter_frames(frames: &[ParsedFrame], spec: &FilterSpec) -> Vec<ParsedFrame> {
    let mut result: Vec<ParsedFrame> = frames
        .iter()
        .filter(|f| {
            if !spec.slave_addresses.is_empty()
                && !spec.slave_addresses.contains(&f.slave_address)
            {
                return false;
            }
            if !frame_type_matches(spec.frame_type, f.frame_type) {
                return false;
            }
            if !diag_condition_satisfied(f, spec) {
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if let Some(limit) = spec.limit {
        result.truncate(limit);
    }

    result
}

pub fn drain_filter_warnings(spec: &mut FilterSpec) -> Vec<String> {
    spec.take_warnings()
        .iter()
        .map(format_filter_warning)
        .collect()
}

pub fn compute_statistics(
    original: &[ParsedFrame],
    filtered: &[ConvertedPdoFrame],
) -> StatisticsSummary {
    let mut slave_counts: HashMap<u8, usize> = HashMap::new();
    let mut slave_names: HashMap<u8, String> = HashMap::new();
    let mut frame_type_counts: HashMap<String, usize> = HashMap::new();
    let mut service_counts: HashMap<String, usize> = HashMap::new();
    let mut diagnostic_counts: HashMap<String, usize> = HashMap::new();
    let mut faults_count = 0usize;

    for f in filtered {
        *slave_counts.entry(f.slave_address).or_insert(0) += 1;
        slave_names
            .entry(f.slave_address)
            .or_insert_with(|| f.slave_name.clone());
        *frame_type_counts.entry(f.frame_type.clone()).or_insert(0) += 1;
        *service_counts
            .entry(f.service_primitive.clone())
            .or_insert(0) += 1;
        if f.bus_fault {
            faults_count += 1;
        }
        for (code, desc) in &f.diagnostic_codes {
            if *code != 0x0000 {
                *diagnostic_counts
                    .entry(format!("0x{:04X} - {}", code, desc))
                    .or_insert(0) += 1;
            }
        }
    }

    let mut slaves: Vec<(u8, String, usize)> = slave_counts
        .iter()
        .map(|(addr, count)| {
            (
                *addr,
                slave_names.get(addr).cloned().unwrap_or_default(),
                *count,
            )
        })
        .collect();
    slaves.sort_by_key(|(a, _, _)| *a);

    StatisticsSummary {
        total_frames: original.len(),
        filtered_frames: filtered.len(),
        faults_count,
        unique_slaves: slaves.len(),
        slaves,
        frame_type_counts,
        service_counts,
        diagnostic_counts,
    }
}

pub fn render_output(
    converted: &[ConvertedPdoFrame],
    stats: &StatisticsSummary,
    format: OutputFormat,
    verbose: bool,
    show_summary: bool,
    output_path: Option<&Path>,
) -> io::Result<()> {
    let mut writer: Box<dyn Write> = match output_path {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(converted)?;
            writeln!(writer, "{}", json)?;
        }
        OutputFormat::JsonPretty => {
            let json = serde_json::to_string_pretty(converted)?;
            writeln!(writer, "{}", json)?;
        }
        OutputFormat::Table => {
            render_table(&mut writer, converted, verbose)?;
            if show_summary {
                render_summary(&mut writer, stats)?;
            }
        }
        OutputFormat::Csv => {
            render_csv(&mut writer, converted)?;
        }
    }

    Ok(())
}

fn render_table(w: &mut dyn Write, frames: &[ConvertedPdoFrame], verbose: bool) -> io::Result<()> {
    if frames.is_empty() {
        writeln!(w, "{}", "⚠  没有匹配的报文帧".yellow().bold())?;
        return Ok(());
    }

    for (idx, frame) in frames.iter().enumerate() {
        let header_line = format!(
            "═ 帧 #{:04}  时间戳: {}ms  从站: [{}] {} ({})  ═",
            idx + 1,
            frame.timestamp,
            frame.slave_address,
            frame.slave_name,
            frame.device_type
        );
        let line_len = header_line.chars().count();
        writeln!(w, "{}", "═".repeat(line_len).blue())?;
        writeln!(
            w,
            "{}",
            header_line.blue().bold()
        )?;
        writeln!(w, "{}", "═".repeat(line_len).blue())?;

        let fault_marker = if frame.bus_fault {
            format!(" {}", "✘ 故障!".red().bold())
        } else {
            format!(" {}", "✔ 正常".green())
        };
        writeln!(
            w,
            "  帧类型: {} | 服务原语: {}{}",
            frame.frame_type.cyan(),
            frame.service_primitive.magenta(),
            fault_marker
        )?;
        if let Some(reason) = &frame.fault_reason {
            writeln!(w, "  {}", format!("故障原因: {}", reason).red().bold())?;
        }
        writeln!(w)?;

        if !frame.input_values.is_empty() {
            writeln!(w, "  {}", "▶ 输入过程数据 (Input PDO)".green().bold())?;
            render_pdo_table(w, &frame.input_values, verbose)?;
            if verbose {
                writeln!(
                    w,
                    "  {} {}",
                    "原始HEX:".dimmed(),
                    frame.raw_input_hex.dimmed()
                )?;
            }
            writeln!(w)?;
        }

        if !frame.output_values.is_empty() {
            writeln!(w, "  {}", "▶ 输出过程数据 (Output PDO)".yellow().bold())?;
            render_pdo_table(w, &frame.output_values, verbose)?;
            if verbose {
                writeln!(
                    w,
                    "  {} {}",
                    "原始HEX:".dimmed(),
                    frame.raw_output_hex.dimmed()
                )?;
            }
            writeln!(w)?;
        }

        if !frame.diagnostic_codes.is_empty() {
            writeln!(w, "  {}", "▶ 诊断码 (Diagnostic Codes)".red().bold())?;
            for (code, desc) in &frame.diagnostic_codes {
                if *code == 0x0000 {
                    writeln!(w, "     [0x{:04X}] {}", code, desc)?;
                } else {
                    writeln!(
                        w,
                        "     {} {}",
                        format!("[0x{:04X}]", code).red().bold(),
                        desc.red()
                    )?;
                }
            }
            writeln!(w)?;
        }
    }

    Ok(())
}

fn render_pdo_table(w: &mut dyn Write, values: &[ConvertedValue], verbose: bool) -> io::Result<()> {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("信号名称").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("类型").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("原始值").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("转换值").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("单位").add_attribute(comfy_table::Attribute::Bold),
        ]);

    for v in values {
        let offset_info = if verbose {
            match v.bit_offset {
                Some(b) => format!("{}@{}.{}", v.data_type, v.offset, b),
                None => format!("{}@{}", v.data_type, v.offset),
            }
        } else {
            v.data_type.clone()
        };

        table.add_row(vec![
            v.description.as_str(),
            offset_info.as_str(),
            v.raw_value.as_str(),
            v.converted_value.as_str(),
            v.unit.as_str(),
        ]);
    }

    writeln!(w, "{}", table)?;
    Ok(())
}

fn render_summary(w: &mut dyn Write, stats: &StatisticsSummary) -> io::Result<()> {
    let line = "═".repeat(60);
    writeln!(w)?;
    writeln!(w, "{}", line.blue().bold())?;
    writeln!(w, "{}", "📊 统计汇总报告".bold().blue())?;
    writeln!(w, "{}", line.blue().bold())?;

    writeln!(w, "  总帧数:        {} 帧", stats.total_frames.to_string().cyan().bold())?;
    writeln!(
        w,
        "  过滤后帧数:    {} 帧",
        stats.filtered_frames.to_string().cyan().bold()
    )?;
    writeln!(
        w,
        "  故障帧数量:    {} 帧",
        stats
            .faults_count
            .to_string()
            .if_greater_than_zero_red()
    )?;
    writeln!(
        w,
        "  活跃从站数:    {} 个",
        stats.unique_slaves.to_string().green().bold()
    )?;
    writeln!(w)?;

    if !stats.slaves.is_empty() {
        writeln!(w, "  {}", "── 从站通信统计 ──".magenta().bold())?;
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic).set_header(vec![
            Cell::new("从站地址").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("设备名称").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("帧数量").add_attribute(comfy_table::Attribute::Bold),
        ]);
        for (addr, name, count) in &stats.slaves {
            table.add_row(vec![
                format!("{}", addr),
                name.clone(),
                format!("{}", count),
            ]);
        }
        writeln!(w, "{}", table)?;
    }

    if !stats.service_counts.is_empty() {
        writeln!(w, "  {}", "── 服务原语统计 ──".magenta().bold())?;
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic).set_header(vec![
            Cell::new("服务类型").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("帧数量").add_attribute(comfy_table::Attribute::Bold),
        ]);
        let mut items: Vec<_> = stats.service_counts.iter().collect();
        items.sort_by(|a, b| b.1.cmp(a.1));
        for (svc, count) in items {
            table.add_row(vec![svc.as_str(), format!("{}", count)]);
        }
        writeln!(w, "{}", table)?;
    }

    if !stats.diagnostic_counts.is_empty() {
        writeln!(w, "  {}", "── 诊断码统计（Top） ──".red().bold())?;
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic).set_header(vec![
            Cell::new("诊断码").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("出现次数").add_attribute(comfy_table::Attribute::Bold),
        ]);
        let mut items: Vec<_> = stats.diagnostic_counts.iter().collect();
        items.sort_by(|a, b| b.1.cmp(a.1));
        for (diag, count) in items.iter().take(10) {
            table.add_row(vec![diag.as_str(), format!("{}", count)]);
        }
        writeln!(w, "{}", table)?;
    }

    Ok(())
}

fn render_csv(w: &mut dyn Write, frames: &[ConvertedPdoFrame]) -> io::Result<()> {
    writeln!(
        w,
        "timestamp,slave_address,slave_name,service_primitive,frame_type,bus_fault,fault_reason,input_hex,output_hex,diag_codes"
    )?;

    for f in frames {
        let diags = f
            .diagnostic_codes
            .iter()
            .map(|(c, _)| format!("0x{:04X}", c))
            .collect::<Vec<_>>()
            .join("|");
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{}",
            f.timestamp,
            f.slave_address,
            csv_escape(&f.slave_name),
            f.service_primitive,
            f.frame_type,
            f.bus_fault,
            csv_escape(&f.fault_reason.clone().unwrap_or_default()),
            csv_escape(&f.raw_input_hex),
            csv_escape(&f.raw_output_hex),
            diags
        )?;
    }

    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn render_template_list(templates: &ProtocolTemplates) {
    println!("{}", "═".repeat(70).blue());
    println!("{}", "📋 内置从站设备 PDO 映射模板".bold().blue());
    println!("{}", "═".repeat(70).blue());

    for tpl in templates.all_templates() {
        println!();
        println!(
            "  {} [地址={}]  厂商标识: 0x{:04X}",
            tpl.name.bold().cyan(),
            tpl.slave_address.to_string().yellow(),
            tpl.vendor_id
        );
        println!("  {}", tpl.description.dimmed());
        println!("  {}", format!("设备类型: {}", tpl.device_type).dimmed());

        if !tpl.input_mappings.is_empty() {
            println!("  {}", "┌ 输入映射 (Input)".green().bold());
            for m in &tpl.input_mappings {
                let bit = m
                    .bit_offset
                    .map(|b| format!(".{}", b))
                    .unwrap_or_default();
                let unit = m
                    .unit
                    .as_ref()
                    .map(|u| format!(" [{}]", u))
                    .unwrap_or_default();
                let scale = m
                    .scale
                    .map(|s| format!(" ×{}", s))
                    .unwrap_or_default();
                println!(
                    "  │  @{:<3}{} {:<10} {}{}{}",
                    format!("{}", m.offset),
                    bit,
                    format!("{:?}", m.data_type),
                    m.description,
                    scale,
                    unit
                );
            }
            println!("  └");
        }

        if !tpl.output_mappings.is_empty() {
            println!("  {}", "┌ 输出映射 (Output)".yellow().bold());
            for m in &tpl.output_mappings {
                let bit = m
                    .bit_offset
                    .map(|b| format!(".{}", b))
                    .unwrap_or_default();
                let unit = m
                    .unit
                    .as_ref()
                    .map(|u| format!(" [{}]", u))
                    .unwrap_or_default();
                let scale = m
                    .scale
                    .map(|s| format!(" ×{}", s))
                    .unwrap_or_default();
                println!(
                    "  │  @{:<3}{} {:<10} {}{}{}",
                    format!("{}", m.offset),
                    bit,
                    format!("{:?}", m.data_type),
                    m.description,
                    scale,
                    unit
                );
            }
            println!("  └");
        }
    }

    println!();
    println!("{}", "═".repeat(70).blue());
}

pub fn render_diag_help(code: Option<u16>) {
    use crate::protocol_parser::ProtocolParser;

    println!("{}", "═".repeat(70).blue());
    println!("{}", "🔧 PROFIBUS-DP 诊断码帮助".bold().blue());
    println!("{}", "═".repeat(70).blue());

    match code {
        Some(c) => {
            let diag = ProtocolParser::lookup_diagnostic_code(c);
            println!();
            println!("  诊断码: 0x{:04X} ({})", c, c);
            println!("  描述:   {}", diag.description.bold());
            if c == 0x0000 {
                println!("  状态:   {}", "正常 - 无诊断事件".green().bold());
            } else {
                println!("  状态:   {}", "异常 - 需要排查".red().bold());
            }
        }
        None => {
            println!();
            println!("{}", "  常用诊断码速查:".bold());
            let common = [
                (0x0000u16, "无诊断 - 设备正常"),
                (0x0001, "站点故障"),
                (0x0002, "站不存在 - 检查从站地址与总线连接"),
                (0x0003, "资源故障 - 从站资源不足"),
                (0x0004, "参数化故障 - 检查 SetPrm 参数"),
                (0x0005, "配置故障 - 检查 ChkCfg 组态"),
                (0x0006, "扩展诊断存在 - 查看后续扩展诊断"),
                (0x0007, "不支持的功能"),
                (0x0008, "模块不存在 - 检查模块插入位置"),
                (0x0014, "低于下限 - 模拟量低于设定阈值"),
                (0x0015, "低于下限 - 模拟量低于设定阈值"),
                (0x001A, "断线 - 检测到传感器/执行器断线"),
                (0x001B, "短路 - 检测到通道短路"),
                (0x001E, "看门狗超时 - 从站未按时响应"),
            ];
            for (c, desc) in common {
                let marker = if c == 0x0000 { "✔".green() } else { "⚠".yellow() };
                println!(
                    "  {} 0x{:04X}  {}",
                    marker,
                    c,
                    desc
                );
            }
            println!();
            println!("{}", "  提示: 使用 show-diag -c <code> 查询指定诊断码".dimmed());
        }
    }
    println!("{}", "═".repeat(70).blue());
}

trait ConditionalColor {
    fn if_greater_than_zero_red(&self) -> ColoredString;
}

impl ConditionalColor for String {
    fn if_greater_than_zero_red(&self) -> ColoredString {
        if let Ok(n) = self.parse::<usize>() {
            if n > 0 {
                return self.clone().red().bold();
            }
        }
        self.clone().normal()
    }
}

pub struct LiveStreamWriter {
    writer: Box<dyn Write>,
    format: OutputFormat,
    verbose: bool,
    frame_count: u64,
    first_frame: bool,
    csv_header_written: bool,
}

impl LiveStreamWriter {
    pub fn new(format: OutputFormat, verbose: bool, output_path: Option<&Path>) -> io::Result<Self> {
        let writer: Box<dyn Write> = match output_path {
            Some(p) => Box::new(File::create(p)?),
            None => Box::new(io::stdout()),
        };
        Ok(Self {
            writer,
            format,
            verbose,
            frame_count: 0,
            first_frame: true,
            csv_header_written: false,
        })
    }

    pub fn write_frame(&mut self, frame: &ConvertedPdoFrame) -> io::Result<()> {
        self.frame_count += 1;
        match self.format {
            OutputFormat::Table => {
                self.write_single_frame_table(frame)?;
            }
            OutputFormat::Json | OutputFormat::JsonPretty => {
                self.write_single_frame_json(frame)?;
            }
            OutputFormat::Csv => {
                self.write_single_frame_csv(frame)?;
            }
        }
        self.writer.flush()?;
        Ok(())
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    fn write_single_frame_table(&mut self, frame: &ConvertedPdoFrame) -> io::Result<()> {
        let w = &mut self.writer;
        let header_line = format!(
            "═ 帧 #{:06}  时间: {}ms  从站: [{}] {} ({})  ═",
            self.frame_count,
            frame.timestamp,
            frame.slave_address,
            frame.slave_name,
            frame.device_type
        );
        let line_len = header_line.chars().count();
        writeln!(w, "{}", "═".repeat(line_len).blue())?;
        writeln!(w, "{}", header_line.blue().bold())?;
        writeln!(w, "{}", "═".repeat(line_len).blue())?;

        let fault_marker = if frame.bus_fault {
            format!(" {}", "✘ 故障!".red().bold())
        } else {
            format!(" {}", "✔ 正常".green())
        };
        writeln!(
            w,
            "  帧类型: {} | 服务原语: {}{}",
            frame.frame_type.cyan(),
            frame.service_primitive.magenta(),
            fault_marker
        )?;
        if let Some(reason) = &frame.fault_reason {
            writeln!(w, "  {}", format!("故障原因: {}", reason).red().bold())?;
        }
        writeln!(w)?;

        if !frame.input_values.is_empty() {
            writeln!(w, "  {}", "▶ 输入过程数据 (Input PDO)".green().bold())?;
            render_pdo_table(w, &frame.input_values, self.verbose)?;
            if self.verbose {
                writeln!(w, "  {} {}", "原始HEX:".dimmed(), frame.raw_input_hex.dimmed())?;
            }
            writeln!(w)?;
        }

        if !frame.output_values.is_empty() {
            writeln!(w, "  {}", "▶ 输出过程数据 (Output PDO)".yellow().bold())?;
            render_pdo_table(w, &frame.output_values, self.verbose)?;
            if self.verbose {
                writeln!(w, "  {} {}", "原始HEX:".dimmed(), frame.raw_output_hex.dimmed())?;
            }
            writeln!(w)?;
        }

        if !frame.diagnostic_codes.is_empty() {
            writeln!(w, "  {}", "▶ 诊断码 (Diagnostic Codes)".red().bold())?;
            for (code, desc) in &frame.diagnostic_codes {
                if *code == 0x0000 {
                    writeln!(w, "     [0x{:04X}] {}", code, desc)?;
                } else {
                    writeln!(
                        w,
                        "     {} {}",
                        format!("[0x{:04X}]", code).red().bold(),
                        desc.red()
                    )?;
                }
            }
            writeln!(w)?;
        }
        Ok(())
    }

    fn write_single_frame_json(&mut self, frame: &ConvertedPdoFrame) -> io::Result<()> {
        let json = if matches!(self.format, OutputFormat::JsonPretty) {
            serde_json::to_string_pretty(frame)?
        } else {
            serde_json::to_string(frame)?
        };
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    fn write_single_frame_csv(&mut self, frame: &ConvertedPdoFrame) -> io::Result<()> {
        if !self.csv_header_written {
            writeln!(
                self.writer,
                "seq,timestamp,slave_address,slave_name,service_primitive,frame_type,bus_fault,fault_reason,input_hex,output_hex,diag_codes"
            )?;
            self.csv_header_written = true;
        }
        let diags = frame
            .diagnostic_codes
            .iter()
            .map(|(c, _)| format!("0x{:04X}", c))
            .collect::<Vec<_>>()
            .join("|");
        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{}",
            self.frame_count,
            frame.timestamp,
            frame.slave_address,
            csv_escape(&frame.slave_name),
            frame.service_primitive,
            frame.frame_type,
            frame.bus_fault,
            csv_escape(&frame.fault_reason.clone().unwrap_or_default()),
            csv_escape(&frame.raw_input_hex),
            csv_escape(&frame.raw_output_hex),
            diags
        )?;
        Ok(())
    }
}

pub fn render_live_status_line(
    source_name: &str,
    frames_parsed: u64,
    bytes_received: u64,
    frames_dropped: u64,
    faults_detected: u64,
) {
    eprint!(
        "\r{}  已解析: {} 帧  |  字节: {}  |  丢弃: {}  |  故障: {}  |  源: {}",
        "●".green().bold(),
        frames_parsed.to_string().cyan().bold(),
        bytes_received.to_string().cyan(),
        frames_dropped.to_string().yellow(),
        faults_detected.to_string().red(),
        source_name
    );
}

pub fn render_live_header(source_name: &str, filter_active: bool) {
    eprintln!("{}", "═".repeat(70).blue());
    eprintln!(
        "{}  正在实时捕获 PROFIBUS-DP 总线数据",
        "📡".bold().cyan()
    );
    eprintln!("{}  数据源: {}", "   ".dimmed(), source_name.cyan());
    if filter_active {
        eprintln!("{}  过滤器已启用", "   ".dimmed());
    }
    eprintln!("{}  按 Ctrl+C 停止捕获", "   ".dimmed());
    eprintln!("{}", "═".repeat(70).blue());
    eprintln!();
}
