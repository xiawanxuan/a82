use crate::protocol_parser::ParsedFrame;
use crate::protocol_templates::{PdoDataType, PdoMapping, ProtocolTemplates, SlaveTemplate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedValue {
    pub description: String,
    pub raw_value: String,
    pub converted_value: String,
    pub unit: String,
    pub offset: usize,
    pub bit_offset: Option<u8>,
    pub data_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedPdoFrame {
    pub timestamp: u32,
    pub slave_address: u8,
    pub slave_name: String,
    pub device_type: String,
    pub service_primitive: String,
    pub frame_type: String,
    pub input_values: Vec<ConvertedValue>,
    pub output_values: Vec<ConvertedValue>,
    pub diagnostic_codes: Vec<(u16, String)>,
    pub bus_fault: bool,
    pub fault_reason: Option<String>,
    pub raw_input_hex: String,
    pub raw_output_hex: String,
}

pub struct PdoConverter {
    templates: ProtocolTemplates,
}

impl PdoConverter {
    pub fn new(templates: ProtocolTemplates) -> Self {
        Self { templates }
    }

    pub fn convert_frame(&self, frame: &ParsedFrame) -> ConvertedPdoFrame {
        let template = self.templates.get_slave_template(frame.slave_address);
        let slave_name = template
            .map(|t| t.name.clone())
            .unwrap_or_else(|| format!("未知从站_{}", frame.slave_address));
        let device_type = template
            .map(|t| t.device_type.clone())
            .unwrap_or_else(|| "通用设备".to_string());

        let input_values = if let Some(tpl) = template {
            self.convert_mappings(&frame.input_data, &tpl.input_mappings)
        } else {
            self.convert_raw_bytes(&frame.input_data, true)
        };

        let output_values = if let Some(tpl) = template {
            self.convert_mappings(&frame.output_data, &tpl.output_mappings)
        } else {
            self.convert_raw_bytes(&frame.output_data, false)
        };

        let diagnostic_codes = frame
            .diagnostic_data
            .iter()
            .map(|d| (d.code, d.description.to_string()))
            .collect();

        ConvertedPdoFrame {
            timestamp: frame.timestamp,
            slave_address: frame.slave_address,
            slave_name,
            device_type,
            service_primitive: format!("{:?}", frame.service_primitive),
            frame_type: format!("{:?}", frame.frame_type),
            input_values,
            output_values,
            diagnostic_codes,
            bus_fault: frame.bus_fault,
            fault_reason: frame.fault_reason.clone(),
            raw_input_hex: bytes_to_hex(&frame.input_data),
            raw_output_hex: bytes_to_hex(&frame.output_data),
        }
    }

    pub fn convert_frames(&self, frames: &[ParsedFrame]) -> Vec<ConvertedPdoFrame> {
        frames.iter().map(|f| self.convert_frame(f)).collect()
    }

    pub fn templates(&self) -> &ProtocolTemplates {
        &self.templates
    }

    fn convert_mappings(&self, data: &[u8], mappings: &[PdoMapping]) -> Vec<ConvertedValue> {
        let mut result = Vec::new();
        for mapping in mappings {
            if let Some((raw, converted)) = self.extract_value(data, mapping) {
                result.push(ConvertedValue {
                    description: mapping.description.clone(),
                    raw_value: raw,
                    converted_value: converted,
                    unit: mapping.unit.clone().unwrap_or_default(),
                    offset: mapping.offset,
                    bit_offset: mapping.bit_offset,
                    data_type: format!("{:?}", mapping.data_type),
                });
            }
        }
        result
    }

    fn convert_raw_bytes(&self, data: &[u8], is_input: bool) -> Vec<ConvertedValue> {
        let mut result = Vec::new();
        if data.is_empty() {
            return result;
        }
        for (i, &byte) in data.iter().enumerate() {
            result.push(ConvertedValue {
                description: format!("{}{:#04x}", if is_input { "输入字节" } else { "输出字节" }, i),
                raw_value: format!("0x{:02X}", byte),
                converted_value: format!("{}", byte),
                unit: String::new(),
                offset: i,
                bit_offset: None,
                data_type: "UInt8".to_string(),
            });
        }
        result
    }

    fn extract_value(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        match mapping.data_type {
            PdoDataType::Bool => self.extract_bool(data, mapping),
            PdoDataType::Int8 => self.extract_int8(data, mapping),
            PdoDataType::Int16 => self.extract_int16(data, mapping),
            PdoDataType::Int32 => self.extract_int32(data, mapping),
            PdoDataType::UInt8 => self.extract_uint8(data, mapping),
            PdoDataType::UInt16 => self.extract_uint16(data, mapping),
            PdoDataType::UInt32 => self.extract_uint32(data, mapping),
            PdoDataType::Float32 => self.extract_float32(data, mapping),
        }
    }

    fn extract_bool(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset >= data.len() {
            return None;
        }
        let bit = mapping.bit_offset.unwrap_or(0);
        let byte = data[mapping.offset];
        let raw = ((byte >> bit) & 0x01) == 1;
        let raw_str = if raw { "1" } else { "0" }.to_string();
        let conv_str = if raw { "TRUE" } else { "FALSE" }.to_string();
        Some((raw_str, conv_str))
    }

    fn extract_int8(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset >= data.len() {
            return None;
        }
        let raw = data[mapping.offset] as i8;
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_int16(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset + 1 >= data.len() {
            return None;
        }
        let raw = i16::from_le_bytes([data[mapping.offset], data[mapping.offset + 1]]);
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_int32(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset + 3 >= data.len() {
            return None;
        }
        let raw = i32::from_le_bytes([
            data[mapping.offset],
            data[mapping.offset + 1],
            data[mapping.offset + 2],
            data[mapping.offset + 3],
        ]);
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_uint8(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset >= data.len() {
            return None;
        }
        let raw = data[mapping.offset] as u8;
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_uint16(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset + 1 >= data.len() {
            return None;
        }
        let raw = u16::from_le_bytes([data[mapping.offset], data[mapping.offset + 1]]);
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_uint32(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset + 3 >= data.len() {
            return None;
        }
        let raw = u32::from_le_bytes([
            data[mapping.offset],
            data[mapping.offset + 1],
            data[mapping.offset + 2],
            data[mapping.offset + 3],
        ]);
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{}", raw), format!("{:.2}", scaled)))
    }

    fn extract_float32(&self, data: &[u8], mapping: &PdoMapping) -> Option<(String, String)> {
        if mapping.offset + 3 >= data.len() {
            return None;
        }
        let raw = f32::from_le_bytes([
            data[mapping.offset],
            data[mapping.offset + 1],
            data[mapping.offset + 2],
            data[mapping.offset + 3],
        ]);
        let scaled = self.apply_scale(raw as f64, mapping.scale);
        Some((format!("{:.4}", raw), format!("{:.4}", scaled)))
    }

    fn apply_scale(&self, value: f64, scale: Option<f64>) -> f64 {
        match scale {
            Some(s) if s != 0.0 => value * s,
            _ => value,
        }
    }

    pub fn add_slave_template(&mut self, template: SlaveTemplate) {
        self.templates.add_slave_template(template);
    }
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("(空)");
    }
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_parser::{FrameType, ServicePrimitive};
    use crate::protocol_templates::*;

    fn create_test_parsed_frame() -> ParsedFrame {
        ParsedFrame {
            timestamp: 1000,
            frame_type: FrameType::Csf,
            service_primitive: ServicePrimitive::DataExchange,
            master_address: 1,
            slave_address: 3,
            frame_length: 14,
            input_data: vec![0x03, 0x00, 0xE8, 0x03, 0x64, 0x00],
            output_data: vec![0x01, 0x00],
            diagnostic_data: vec![],
            bus_fault: false,
            fault_reason: None,
            fcb: false,
            fcv: true,
        }
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x01, 0x02, 0x03]), "01 02 03");
        assert_eq!(bytes_to_hex(&[]), "(空)");
    }

    #[test]
    fn test_convert_frame_with_template() {
        let templates = ProtocolTemplates::new();
        let converter = PdoConverter::new(templates);
        let frame = create_test_parsed_frame();
        let converted = converter.convert_frame(&frame);

        assert_eq!(converted.slave_address, 3);
        assert_eq!(converted.slave_name, "S7-1200_CPU");
        assert!(converted.input_values.len() >= 2);
    }

    #[test]
    fn test_convert_mappings_bool() {
        let templates = ProtocolTemplates::new();
        let converter = PdoConverter::new(templates);
        let mapping = PdoMapping {
            offset: 0,
            bit_offset: Some(0),
            data_type: PdoDataType::Bool,
            description: "测试位".to_string(),
            unit: None,
            scale: None,
        };
        let data = vec![0x01];
        let result = converter.extract_value(&data, &mapping);
        assert!(result.is_some());
        let (raw, conv) = result.unwrap();
        assert_eq!(raw, "1");
        assert_eq!(conv, "TRUE");
    }

    #[test]
    fn test_convert_mappings_int16_with_scale() {
        let templates = ProtocolTemplates::new();
        let converter = PdoConverter::new(templates);
        let mapping = PdoMapping {
            offset: 0,
            bit_offset: None,
            data_type: PdoDataType::Int16,
            description: "缩放值".to_string(),
            unit: Some("Hz".to_string()),
            scale: Some(0.01),
        };
        let data = vec![0xE8, 0x03];
        let result = converter.extract_value(&data, &mapping);
        assert!(result.is_some());
        let (raw, conv) = result.unwrap();
        assert_eq!(raw, "1000");
        assert_eq!(conv, "10.00");
    }

    #[test]
    fn test_convert_mappings_uint16() {
        let templates = ProtocolTemplates::new();
        let converter = PdoConverter::new(templates);
        let mapping = PdoMapping {
            offset: 0,
            bit_offset: None,
            data_type: PdoDataType::UInt16,
            description: "计数器".to_string(),
            unit: Some("pcs".to_string()),
            scale: None,
        };
        let data = vec![0x64, 0x00];
        let result = converter.extract_value(&data, &mapping);
        assert!(result.is_some());
        let (raw, conv) = result.unwrap();
        assert_eq!(raw, "100");
        assert_eq!(conv, "100.00");
    }
}
