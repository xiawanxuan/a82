mod cli;
mod live_capture;
mod output;
mod packet_reader;
mod pdo_converter;
mod protocol_parser;
mod protocol_templates;

use clap::Parser;
use cli::{CliArgs, Command, LiveSourceKind};
use colored::*;
use live_capture::{CaptureError, LiveCaptureEngine, LiveSourceType, create_capture_source};
use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() -> ExitCode {
    let args = CliArgs::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", "错误:".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        Command::Parse(parse_args) => cmd_parse(parse_args),
        Command::Live(live_args) => cmd_live(live_args),
        Command::ListTemplates => cmd_list_templates(),
        Command::ShowDiagHelp(diag_args) => cmd_show_diag_help(diag_args),
        Command::GenerateSample(sample_args) => cmd_generate_sample(sample_args),
    }
}

fn cmd_parse(
    parse_args: cli::ParseArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = match &parse_args.file {
        Some(path) => {
            if !path.exists() {
                return Err(format!("文件不存在: {}", path.display()).into());
            }
            eprintln!("{} {}", "正在读取文件:".dimmed(), path.display().to_string().cyan());
            packet_reader::PacketReader::from_file(path)?
        }
        None => {
            eprintln!("{}", "等待标准输入数据 (管道模式)...".dimmed());
            packet_reader::PacketReader::from_stdin()?
        }
    };

    let total_bytes = reader.total_len();
    eprintln!(
        "{} {} 字节",
        "已加载数据:".dimmed(),
        total_bytes.to_string().cyan()
    );

    let mut parser = protocol_parser::ProtocolParser::new(reader);
    let all_frames = parser.parse_all_frames()?;
    eprintln!(
        "{} {} 个原始帧",
        "检测到:".dimmed(),
        all_frames.len().to_string().cyan()
    );

    let verbose = parse_args.filter.verbose;
    let show_summary = parse_args.summary;
    let output_format = parse_args.format;
    let output_path = parse_args.output.clone();

    let mut filter_spec = parse_args.normalize_into_filter_spec();

    let warnings = output::drain_filter_warnings(&mut filter_spec);
    for w in &warnings {
        eprintln!("{}", w.yellow());
    }

    let filtered_frames = output::filter_frames(&all_frames, &filter_spec);

    eprintln!(
        "{} {} 个帧",
        "过滤后匹配:".dimmed(),
        filtered_frames.len().to_string().cyan().bold()
    );

    let templates = protocol_templates::ProtocolTemplates::new();
    let converter = pdo_converter::PdoConverter::new(templates);
    let converted = converter.convert_frames(&filtered_frames);
    let stats = output::compute_statistics(&all_frames, &converted);

    let output_path_ref = output_path.as_deref();
    output::render_output(
        &converted,
        &stats,
        output_format,
        verbose,
        show_summary,
        output_path_ref,
    )?;

    if output_path.is_some() {
        let p = output_path.unwrap();
        println!("{} {}", "✓ 结果已写入:".green().bold(), p.display().to_string().cyan());
    }

    Ok(())
}

fn cmd_live(live_args: cli::LiveArgs) -> Result<(), Box<dyn std::error::Error>> {
    let source_kind = live_args.source.clone();
    let addr = live_args.addr.clone();
    let baud = live_args.baud;
    let timeout_ms = live_args.timeout_ms;
    let simulate = live_args.simulate_realtime();
    let output_format = live_args.format;
    let verbose = live_args.filter.verbose;
    let output_path = live_args.output.clone();
    let stats_every = live_args.stats_every;

    let source_type = match source_kind {
        LiveSourceKind::Serial => {
            let path = addr
                .clone()
                .ok_or_else(|| "串口模式必须指定 --addr 参数，例如: --addr COM3".to_string())?;
            LiveSourceType::Serial(path, baud)
        }
        LiveSourceKind::Udp => {
            let addr = addr
                .clone()
                .ok_or_else(|| "UDP 模式必须指定 --addr 参数，例如: --addr 0.0.0.0:9600".to_string())?;
            LiveSourceType::Udp(addr)
        }
        LiveSourceKind::Stdin => LiveSourceType::Stdin,
        LiveSourceKind::File => {
            let path = addr
                .clone()
                .ok_or_else(|| "文件模式必须指定 --addr 参数".to_string())?;
            LiveSourceType::File(path, simulate)
        }
    };

    let source = create_capture_source(source_type, Duration::from_millis(timeout_ms))?;
    let source_name = source.source_name().to_string();
    let mut engine = LiveCaptureEngine::new(source);

    let mut filter_spec = live_args.normalize_into_filter_spec();
    let filter_active = !filter_spec.is_empty();
    let warnings = output::drain_filter_warnings(&mut filter_spec);
    for w in &warnings {
        eprintln!("{}", w.yellow());
    }

    output::render_live_header(&source_name, filter_active);

    let templates = protocol_templates::ProtocolTemplates::new();
    let converter = pdo_converter::PdoConverter::new(templates);

    let mut stream_writer =
        output::LiveStreamWriter::new(output_format, verbose, output_path.as_deref())?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let ctrlc_result = std::panic::catch_unwind(|| {
        signal_hook::flag::register(signal_hook::consts::SIGINT, r).ok();
    });
    let has_signal_handler = ctrlc_result.is_ok();

    let mut faults_detected: u64 = 0;
    let mut stats_counter: u64 = 0;

    let limit = filter_spec.limit;
    let filter_spec = filter_spec;

    loop {
        if has_signal_handler && !running.load(Ordering::Relaxed) {
            break;
        }

        match engine.poll_frame() {
            Ok(Some(frame)) => {
                let mut matches = true;
                if filter_active {
                    let single = std::slice::from_ref(&frame);
                    let filtered =
                        output::filter_frames(single, &filter_spec);
                    matches = !filtered.is_empty();
                }

                if matches {
                    let converted = converter.convert_frame(&frame);
                    if converted.bus_fault {
                        faults_detected += 1;
                    }
                    stream_writer.write_frame(&converted)?;

                    if let Some(lim) = limit {
                        if stream_writer.frame_count() >= lim as u64 {
                            break;
                        }
                    }
                }

                if stats_every > 0 {
                    stats_counter += 1;
                    if stats_counter >= stats_every {
                        stats_counter = 0;
                        let (parsed, dropped, bytes) = engine.stats();
                        output::render_live_status_line(
                            &source_name,
                            parsed,
                            bytes,
                            dropped,
                            faults_detected,
                        );
                    }
                }
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(CaptureError::Stopped) => break,
            Err(CaptureError::Timeout) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(format!("捕获错误: {}", e).into());
            }
        }
    }

    eprintln!();
    eprintln!("{}", "═".repeat(70).blue());
    let (parsed, dropped, bytes) = engine.stats();
    eprintln!(
        "{} 捕获结束 - 解析 {} 帧 | 字节 {} | 丢弃 {} | 故障 {}",
        "📊".bold().cyan(),
        parsed.to_string().cyan().bold(),
        bytes.to_string().cyan(),
        dropped.to_string().yellow(),
        faults_detected.to_string().red()
    );
    eprintln!("{}", "═".repeat(70).blue());

    if output_path.is_some() {
        let p = output_path.unwrap();
        println!("{} {}", "✓ 结果已写入:".green().bold(), p.display().to_string().cyan());
    }

    Ok(())
}

fn cmd_list_templates() -> Result<(), Box<dyn std::error::Error>> {
    let templates = protocol_templates::ProtocolTemplates::new();
    output::render_template_list(&templates);
    Ok(())
}

fn cmd_show_diag_help(
    diag_args: cli::DiagHelpArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let code = diag_args.code.as_ref().and_then(|s| cli::parse_hex_or_dec(s));
    output::render_diag_help(code);
    Ok(())
}

fn cmd_generate_sample(
    sample_args: cli::GenerateSampleArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = generate_sample_capture(sample_args.frames);
    let mut file = File::create(&sample_args.file)?;
    file.write_all(&data)?;
    println!(
        "{} {} (共 {} 帧, {} 字节)",
        "✓ 示例抓包文件已生成:".green().bold(),
        sample_args.file.display().to_string().cyan(),
        sample_args.frames,
        data.len()
    );
    println!();
    println!("{}", "下一步操作:".yellow().bold());
    println!(
        "  {} {}",
        "$ profibus-dp-analyzer parse -f".white(),
        sample_args.file.display().to_string().cyan()
    );
    println!(
        "  {} {}",
        "$ profibus-dp-analyzer parse -f <file> --json-pretty -s 3,5".white()
    );
    Ok(())
}

fn generate_sample_capture(frame_count: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut buffer = Vec::new();

    for i in 0..frame_count {
        let slave_pool = [3u8, 5, 7, 10, 2, 15];
        let slave_addr = slave_pool[i % slave_pool.len()];
        let master_addr = 1u8;

        let is_response = (i % 2) == 1;
        let fc = if is_response { 0xF7u8 } else { 0xF4u8 };

        let pdu: Vec<u8> = match i % 5 {
            0 => {
                let len = 6;
                let mut p = vec![0x00u8; len];
                for b in p.iter_mut() {
                    *b = rng.random_range(0..=255);
                }
                p
            }
            1 if !is_response => {
                let mut p = vec![0x5Eu8];
                p.extend_from_slice(&[0u8; 4]);
                p
            }
            2 => {
                let mut p = vec![0x00u8; 4];
                for b in p.iter_mut() {
                    *b = rng.random_range(0..=255);
                }
                p
            }
            3 if !is_response => {
                let mut p = vec![0x51u8];
                p.extend_from_slice(&[0x01, 0x00, 0xFF, 0xFF, 0x00, 0x00]);
                p
            }
            4 if is_response => {
                let mut p = vec![0x5Eu8, 0x01];
                p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]);
                p
            }
            _ => vec![0x00u8; 4],
        };

        let total_len: u8 = (6 + pdu.len() + 2) as u8;
        let mut frame = vec![
            0x10,
            total_len,
            total_len,
            fc,
            slave_addr,
            master_addr,
        ];
        frame.extend_from_slice(&pdu);
        let fcs = frame[4..frame.len()].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        frame.push(fcs);
        frame.push(0x16);

        if i % 7 == 0 {
            let padding: Vec<u8> = (0..3).map(|_| rng.random_range(0..=255)).collect();
            buffer.extend_from_slice(&padding);
        }
        buffer.extend_from_slice(&frame);
    }

    buffer
}
