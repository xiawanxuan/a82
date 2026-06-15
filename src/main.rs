mod cli;
mod output;
mod packet_reader;
mod pdo_converter;
mod protocol_parser;
mod protocol_templates;

use clap::Parser;
use cli::{CliArgs, Command};
use colored::*;
use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

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

    let filtered_frames = output::filter_frames(
        &all_frames,
        &parse_args.slave_filter,
        parse_args.frame_type,
        parse_args.diag_code_filter(),
        parse_args.faults_only,
    );

    let mut limited_frames: Vec<protocol_parser::ParsedFrame> = filtered_frames;
    if let Some(limit) = parse_args.limit {
        if limit > 0 {
            limited_frames.truncate(limit);
        }
    }

    eprintln!(
        "{} {} 个帧",
        "过滤后匹配:".dimmed(),
        limited_frames.len().to_string().cyan().bold()
    );

    let templates = protocol_templates::ProtocolTemplates::new();
    let converter = pdo_converter::PdoConverter::new(templates);
    let converted = converter.convert_frames(&limited_frames);
    let stats = output::compute_statistics(&all_frames, &converted);

    let output_path_ref = parse_args.output.as_deref();
    output::render_output(
        &converted,
        &stats,
        parse_args.format,
        parse_args.verbose,
        parse_args.summary,
        output_path_ref,
    )?;

    if parse_args.output.is_some() {
        let p = parse_args.output.unwrap();
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
