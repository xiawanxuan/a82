use crate::packet_reader::PacketReader;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Srd,
    SrdHigh,
    SrdLow,
    Sda,
    Csf,
    FdlStatus,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServicePrimitive {
    DataExchange,
    SlaveDiagnostic,
    SetPrm,
    ChkCfg,
    SetSlaveAdd,
    ReadInput,
    ReadOutput,
    GlobalControl,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCode {
    pub code: u16,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFrame {
    pub timestamp: u32,
    pub frame_type: FrameType,
    pub service_primitive: ServicePrimitive,
    pub master_address: u8,
    pub slave_address: u8,
    pub frame_length: usize,
    pub input_data: Vec<u8>,
    pub output_data: Vec<u8>,
    pub diagnostic_data: Vec<DiagnosticCode>,
    pub bus_fault: bool,
    pub fault_reason: Option<String>,
    pub fcb: bool,
    pub fcv: bool,
}

#[derive(Debug)]
pub enum ParseError {
    Io(std::io::Error),
    InvalidFrame(String),
    InvalidChecksum,
    InsufficientData,
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> Self {
        ParseError::Io(err)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {}", e),
            ParseError::InvalidFrame(m) => write!(f, "Invalid frame: {}", m),
            ParseError::InvalidChecksum => write!(f, "Invalid checksum"),
            ParseError::InsufficientData => write!(f, "Insufficient data"),
        }
    }
}

pub struct ProtocolParser {
    reader: PacketReader,
    start_delimiter: u8,
}

impl ProtocolParser {
    pub fn new(reader: PacketReader) -> Self {
        Self {
            reader,
            start_delimiter: 0x10,
        }
    }

    pub fn parse_all_frames(&mut self) -> Result<Vec<ParsedFrame>, ParseError> {
        let mut frames = Vec::new();
        let mut frame_offsets = self.find_frame_offsets()?;
        
        for offset in frame_offsets {
            self.reader.seek(offset)?;
            match self.parse_single_frame() {
                Ok(frame) => frames.push(frame),
                Err(e) => {
                    eprintln!("Warning: Failed to parse frame at offset {}: {}", offset, e);
                }
            }
        }
        
        Ok(frames)
    }

    fn find_frame_offsets(&mut self) -> Result<Vec<usize>> {
        let mut offsets = Vec::new();
        let data = self.reader.as_slice();
        let mut i = 0;
        
        while i < data.len().saturating_sub(3) {
            if data[i] == self.start_delimiter && i + 3 < data.len() {
                let length = data[i + 1] as usize;
                if length >= 6 && i + length <= data.len() {
                    offsets.push(i);
                    i += length;
                    continue;
                }
            }
            i += 1;
        }
        
        Ok(offsets)
    }

    fn parse_single_frame(&mut self) -> Result<ParsedFrame, ParseError> {
        let start_pos = self.reader.position();
        
        let sd = self.reader.read_u8()?;
        if sd != self.start_delimiter {
            return Err(ParseError::InvalidFrame(format!(
                "Invalid start delimiter: 0x{:02X}",
                sd
            )));
        }

        let length = self.reader.read_u8()? as usize;
        if length < 6 {
            return Err(ParseError::InvalidFrame(format!(
                "Frame too short: {}",
                length
            ));
        }

        let le = self.reader.read_u8()?;
        if le != length as u8 {
            return Err(ParseError::InvalidFrame(
                "Length field mismatch".to_string(),
            ));
        }

        let fc = self.reader.read_u8()?;
        let frame_type = Self::decode_frame_type(fc);
        let (fcb, fcv) = ((fc & 0x20) != 0, (fc & 0x10) != 0);

        let da = self.reader.read_u8()?;
        let sa = self.reader.read_u8()?;

        let data_length = length - 6;
        let _pdu_data = if data_length > 0 {
            self.reader.read_bytes(data_length)?
        } else {
            &[]
        };

        let fcs = self.reader.read_u8()?;
        let ed = self.reader.read_u8()?;

        if ed != 0x16 {
            return Err(ParseError::InvalidFrame(format!(
                "Invalid end delimiter: 0x{:02X}",
                ed
            )));
        }

        let actual_length = self.reader.position() - start_pos;
        if !self.verify_checksum(start_pos, actual_length - 2, fcs) {
            return Err(ParseError::InvalidChecksum);
        }

        let timestamp = (start_pos as u32) * 1000;

        let (input_data, output_data, service_primitive, diagnostic_data, bus_fault, fault_reason) =
            self.decode_pdu_data(&_pdu_data, frame_type)?;

        Ok(ParsedFrame {
            timestamp,
            frame_type,
            service_primitive,
            master_address: sa,
            slave_address: da & 0x7F,
            frame_length: length,
            input_data,
            output_data,
            diagnostic_data,
            bus_fault,
            fault_reason,
            fcb,
            fcv,
        })
    }

    fn decode_frame_type(fc: u8) -> FrameType {
        match fc & 0x0F {
            0x04 | 0x05 | 0x06 | 0x07 => FrameType::Srd,
            0x0A => FrameType::Sda,
            0x0E => FrameType::Csf,
            0x0F => FrameType::FdlStatus,
            _ => FrameType::Unknown,
        }
    }

    fn decode_pdu_data(
        &self,
        pdu_data: &[u8],
        frame_type: FrameType,
    ) -> Result<(Vec<u8>, Vec<u8>, ServicePrimitive, Vec<DiagnosticCode>, bool, Option<String>), ParseError>
    {
        if pdu_data.is_empty() {
            return Ok((vec![], vec![], ServicePrimitive::Unknown, vec![], false, None));
        }

        let mut input_data = Vec::new();
        let mut output_data = Vec::new();
        let mut diagnostic_codes = Vec::new();
        let mut bus_fault = false;
        let mut fault_reason = None;

        let service_primitive = match pdu_data[0] {
            0x00..=0x3F => {
                let is_response = frame_type == FrameType::Csf;
                if is_response && pdu_data.len() > 1 {
                    diagnostic_codes = Self::decode_diagnostic_data(&pdu_data[1..]);
                }
                ServicePrimitive::DataExchange
            }
            0x5E => ServicePrimitive::SlaveDiagnostic,
            0x51 => ServicePrimitive::SetPrm,
            0x52 => ServicePrimitive::ChkCfg,
            0x55 => ServicePrimitive::SetSlaveAdd,
            0x56 => ServicePrimitive::ReadInput,
            0x57 => ServicePrimitive::ReadOutput,
            0x58 => ServicePrimitive::GlobalControl,
            _ => ServicePrimitive::Unknown,
        };

        if service_primitive == ServicePrimitive::DataExchange {
            let is_response = frame_type == FrameType::Csf;
            if is_response {
                input_data = pdu_data[1..].to_vec();
            } else {
                output_data = pdu_data[1..].to_vec();
            }
        }

        if service_primitive == ServicePrimitive::SlaveDiagnostic {
            diagnostic_codes = Self::decode_diagnostic_data(&pdu_data[1..]);
            if !diagnostic_codes.is_empty() {
                bus_fault = diagnostic_codes.iter().any(|d| d.code != 0x0000);
                if bus_fault {
                    fault_reason = diagnostic_codes
                        .iter()
                        .find(|d| d.code != 0x0000)
                        .map(|d| d.description.to_string());
                }
            }
        }

        Ok((
            input_data,
            output_data,
            service_primitive,
            diagnostic_codes,
            bus_fault,
            fault_reason,
        ))
    }

    fn decode_diagnostic_data(data: &[u8]) -> Vec<DiagnosticCode> {
        let mut codes = Vec::new();

        if data.is_empty() {
            return codes;
        }

        let master_diag = data[0];
        if master_diag != 0 {
            codes.push(Self::lookup_diagnostic_code(master_diag as u16));
        }

        if data.len() >= 2 {
            let ident_number = if data.len() >= 4 {
                u16::from_le_bytes([data[2], data[3]])
            } else {
                0
            };
            if ident_number != 0 {
                codes.push(Self::lookup_diagnostic_code(ident_number));
            }
        }

        if data.len() >= 6 {
            let mut offset = 6;
            while offset + 3 <= data.len() {
                let ext_diag_code = u16::from_le_bytes([data[offset], data[offset + 1]]);
                if ext_diag_code != 0 {
                    codes.push(Self::lookup_diagnostic_code(ext_diag_code));
                }
                offset += 3;
            }
        }

        if codes.is_empty() {
            codes.push(Self::lookup_diagnostic_code(0x0000));
        }

        codes
    }

    pub fn lookup_diagnostic_code(code: u16) -> DiagnosticCode {
        let description = match code {
            0x0000 => "无诊断",
            0x0001 => "站点故障",
            0x0002 => "站不存在",
            0x0003 => "资源故障",
            0x0004 => "参数化故障",
            0x0005 => "配置故障",
            0x0006 => "扩展诊断存在",
            0x0007 => "不支持的功能",
            0x0008 => "模块不存在",
            0x0009 => "组态数据长度错误",
            0x000A => "参数数据错误",
            0x000B => "操作模式错误",
            0x000C => "配置数据错误",
            0x000D => "重复的模块不存在",
            0x000E => "模块故障",
            0x000F => "模块参数化错误",
            0x0010 => "配置故障",
            0x0011 => "模块不存在",
            0x0012 => "模块故障",
            0x0013 => "未使用的通道短路",
            0x0014 => "过载",
            0x0015 => "低压",
            0x0016 => "熔断器熔断",
            0x0017 => "没有外部辅助电压",
            0x0018 => "超出上限",
            0x0019 => "低于下限",
            0x001A => "断线",
            0x001B => "短路",
            0x001C => "电源故障",
            0x001D => "通道故障",
            0x001E => "看门狗超时",
            0x001F => "过程数据长度错误",
            0x0020 => "站返回的过程数据长度不一致",
            0x0021 => "制造商特定诊断",
            0x0022 => "通道诊断",
            0x0023 => "用户故障",
            0x0024 => "槽位不存在",
            0x0025 => "电缆断裂",
            0x0026 => "硬件中断丢失",
            0x0027 => "访问被拒绝",
            0x0028 => "DP 从站只运行模式下数据传输被禁止",
            0x0029 => "同步模式下的全局控制命令",
            0x002A => "SYNC 帧受到干扰",
            0x002B => "FREEZE 帧受到干扰",
            0x002C => "看门狗超时",
            0x002D => "新的参数化数据",
            0x002E => "静态诊断",
            0x002F => "优先级 4 优先级 5 的报文头错误",
            0x0030 => "协议错误 信息类型 1",
            0x0031 => "协议错误 信息类型 2",
            0x0032 => "协议错误 信息类型 3",
            0x0033 => "协议错误 信息类型 4",
            0x0034 => "协议错误 信息类型 5",
            0x0035 => "协议错误 信息类型 6",
            0x0036 => "协议错误 信息类型 7",
            0x0037 => "主站不活跃",
            0x0038 => "配置故障 配置故障",
            0x0039 => "参数化故障",
            0x003A => "类型不一致",
            0x003B => "DP 从站被新的主站参数化",
            0x003C => "无用户数据错误",
            0x003D => "命令被禁止",
            0x003E => "无效的从站状态",
            0x003F => "诊断溢出",
            0x0040 => "诊断溢出",
            _ => "未知诊断代码",
        };

        DiagnosticCode { code, description }
    }

    fn verify_checksum(&self, start_pos: usize, length: usize, expected_fcs: u8) -> bool {
        let data = self.reader.as_slice();
        if start_pos + length > data.len() {
            return false;
        }
        
        let mut fcs: u8 = 0;
        for &byte in &data[start_pos + 4..start_pos + 4 + length.saturating_sub(4)] {
            fcs = fcs.wrapping_add(byte);
        }
        
        fcs == expected_fcs
    }

    pub fn into_inner(self) -> PacketReader {
        self.reader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_reader::DataSource;

    #[test]
    fn test_decode_frame_type() {
        assert_eq!(ProtocolParser::decode_frame_type(0xF7), FrameType::Srd);
        assert_eq!(ProtocolParser::decode_frame_type(0xFA), FrameType::Sda);
    }

    #[test]
    fn test_lookup_diagnostic_code() {
        let code = ProtocolParser::lookup_diagnostic_code(0x0000);
        assert_eq!(code.description, "无诊断");

        let code = ProtocolParser::lookup_diagnostic_code(0xFFFF);
        assert_eq!(code.description, "未知诊断代码");
    }

    fn create_test_frame() -> Vec<u8> {
        let pdu: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03];
        let total_len: u8 = (6 + pdu.len() + 2) as u8;
        let mut frame = vec![
            0x10,
            total_len,
            total_len,
            0xF7,
            0x03,
            0x02,
        ];
        frame.extend_from_slice(&pdu);
        let fcs = frame[4..frame.len()].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        frame.push(fcs);
        frame.push(0x16);
        frame
    }

    fn create_diagnostic_frame() -> Vec<u8> {
        let pdu: Vec<u8> = vec![0x5E, 0x00, 0x00, 0x00, 0x00, 0x00];
        let total_len: u8 = (6 + pdu.len() + 2) as u8;
        let mut frame = vec![
            0x10,
            total_len,
            total_len,
            0xF7,
            0x05,
            0x01,
        ];
        frame.extend_from_slice(&pdu);
        let fcs = frame[4..frame.len()].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        frame.push(fcs);
        frame.push(0x16);
        frame
    }

    #[test]
    fn test_parse_frame() {
        let data = create_test_frame();
        let reader = PacketReader {
            source: DataSource::Stdin,
            buffer: data,
            position: 0,
        };
        let mut parser = ProtocolParser::new(reader);
        let frames = parser.parse_all_frames().unwrap();
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.slave_address, 3);
        assert_eq!(frame.master_address, 2);
        assert_eq!(frame.service_primitive, ServicePrimitive::DataExchange);
    }

    #[test]
    fn test_parse_diagnostic_frame() {
        let data = create_diagnostic_frame();
        let reader = PacketReader {
            source: DataSource::Stdin,
            buffer: data,
            position: 0,
        };
        let mut parser = ProtocolParser::new(reader);
        let frames = parser.parse_all_frames().unwrap();
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.slave_address, 5);
        assert_eq!(frame.service_primitive, ServicePrimitive::SlaveDiagnostic);
        assert!(!frame.diagnostic_data.is_empty());
    }
}
