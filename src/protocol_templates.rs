use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdoMapping {
    pub offset: usize,
    pub bit_offset: Option<u8>,
    pub data_type: PdoDataType,
    pub description: String,
    pub unit: Option<String>,
    pub scale: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveTemplate {
    pub slave_address: u8,
    pub name: String,
    pub description: String,
    pub input_mappings: Vec<PdoMapping>,
    pub output_mappings: Vec<PdoMapping>,
    pub device_type: String,
    pub vendor_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdoDataType {
    Bool,
    Int8,
    Int16,
    Int32,
    UInt8,
    UInt16,
    UInt32,
    Float32,
}

#[derive(Debug, Clone)]
pub struct ProtocolTemplates {
    slaves: HashMap<u8, SlaveTemplate>,
}

impl ProtocolTemplates {
    pub fn new() -> Self {
        let mut templates = Self {
            slaves: HashMap::new(),
        };
        templates.load_default_templates();
        templates
    }

    fn load_default_templates(&mut self) {
        self.add_slave_template(SlaveTemplate {
            slave_address: 3,
            name: "S7-1200_CPU".to_string(),
            description: "西门子 S7-1200 PLC 从站".to_string(),
            device_type: "S7-1200".to_string(),
            vendor_id: 0x002A,
            input_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(0),
                    data_type: PdoDataType::Bool,
                    description: "传送带运行状态".to_string(),
                    unit: None,
                    scale: None,
                },
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(1),
                    data_type: PdoDataType::Bool,
                    description: "传送带故障".to_string(),
                    unit: None,
                    scale: None,
                },
                PdoMapping {
                    offset: 2,
                    bit_offset: None,
                    data_type: PdoDataType::Int16,
                    description: "电机转速".to_string(),
                    unit: Some("RPM".to_string()),
                    scale: Some(1.0),
                },
                PdoMapping {
                    offset: 4,
                    bit_offset: None,
                    data_type: PdoDataType::UInt16,
                    description: "产品计数器".to_string(),
                    unit: Some("pcs".to_string()),
                    scale: None,
                },
            ],
            output_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(0),
                    data_type: PdoDataType::Bool,
                    description: "传送带启动命令".to_string(),
                    unit: None,
                    scale: None,
                },
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(1),
                    data_type: PdoDataType::Bool,
                    description: "传送带停止命令".to_string(),
                    unit: None,
                    scale: None,
                },
            ],
        });

        self.add_slave_template(SlaveTemplate {
            slave_address: 5,
            name: "ET200S_IO".to_string(),
            description: "西门子 ET200S 远程 IO 站".to_string(),
            device_type: "ET200S".to_string(),
            vendor_id: 0x002A,
            input_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: None,
                    data_type: PdoDataType::UInt16,
                    description: "模拟量输入通道1 - 温度".to_string(),
                    unit: Some("°C".to_string()),
                    scale: Some(0.1),
                },
                PdoMapping {
                    offset: 2,
                    bit_offset: None,
                    data_type: PdoDataType::UInt16,
                    description: "模拟量输入通道2 - 压力".to_string(),
                    unit: Some("bar".to_string()),
                    scale: Some(0.01),
                },
            ],
            output_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(0),
                    data_type: PdoDataType::Bool,
                    description: "电磁阀1控制".to_string(),
                    unit: None,
                    scale: None,
                },
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(1),
                    data_type: PdoDataType::Bool,
                    description: "电磁阀2控制".to_string(),
                    unit: None,
                    scale: None,
                },
            ],
        });

        self.add_slave_template(SlaveTemplate {
            slave_address: 7,
            name: "MM440_VFD".to_string(),
            description: "西门子 MM440 变频器".to_string(),
            device_type: "MM440".to_string(),
            vendor_id: 0x002A,
            input_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: None,
                    data_type: PdoDataType::Int16,
                    description: "实际转速反馈".to_string(),
                    unit: Some("Hz".to_string()),
                    scale: Some(0.01),
                },
                PdoMapping {
                    offset: 2,
                    bit_offset: None,
                    data_type: PdoDataType::Int16,
                    description: "实际电流".to_string(),
                    unit: Some("A".to_string()),
                    scale: Some(0.1),
                },
            ],
            output_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: None,
                    data_type: PdoDataType::Int16,
                    description: "设定频率设定值".to_string(),
                    unit: Some("Hz".to_string()),
                    scale: Some(0.01),
                },
            ],
        });

        self.add_slave_template(SlaveTemplate {
            slave_address: 10,
            name: "FESTO_Cylinder".to_string(),
            description: "FESTO 气缸阀岛".to_string(),
            device_type: "CPX-FB13".to_string(),
            vendor_id: 0x0076,
            input_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(0),
                    data_type: PdoDataType::Bool,
                    description: "气缸A 伸出到位".to_string(),
                    unit: None,
                    scale: None,
                },
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(1),
                    data_type: PdoDataType::Bool,
                    description: "气缸A 缩回到位".to_string(),
                    unit: None,
                    scale: None,
                },
            ],
            output_mappings: vec![
                PdoMapping {
                    offset: 0,
                    bit_offset: Some(0),
                    data_type: PdoDataType::Bool,
                    description: "气缸A 伸出".to_string(),
                    unit: None,
                    scale: None,
                },
            ],
        });
    }

    pub fn add_slave_template(&mut self, template: SlaveTemplate) {
        self.slaves.insert(template.slave_address, template);
    }

    pub fn get_slave_template(&self, address: u8) -> Option<&SlaveTemplate> {
        self.slaves.get(&address)
    }

    pub fn all_templates(&self) -> Vec<&SlaveTemplate> {
        self.slaves.values().collect()
    }

    pub fn describe_input_mapping(
        &self,
        slave_address: u8,
        is_input: bool,
        offset: usize,
    ) -> Option<&PdoMapping> {
        let template = self.slaves.get(&slave_address)?;
        let mappings = if is_input {
            &template.input_mappings
        } else {
            &template.output_mappings
        };
        mappings
            .iter()
            .find(|m| {
                if m.bit_offset.is_some() {
                    m.offset == offset
                } else {
                    m.offset <= offset && offset < m.offset + Self::type_size(m.data_type)
                }
            })
    }

    fn type_size(data_type: PdoDataType) -> usize {
        match data_type {
            PdoDataType::Bool | PdoDataType::Int8 | PdoDataType::UInt8 => 1,
            PdoDataType::Int16 | PdoDataType::UInt16 => 2,
            PdoDataType::Int32 | PdoDataType::UInt32 | PdoDataType::Float32 => 4,
        }
    }
}

impl Default for ProtocolTemplates {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_creation() {
        let templates = ProtocolTemplates::new();
        assert!(templates.get_slave_template(3).is_some());
        assert!(templates.get_slave_template(5).is_some());
        assert!(templates.get_slave_template(7).is_some());
        assert!(templates.get_slave_template(10).is_some());
    }

    #[test]
    fn test_describe_mapping() {
        let templates = ProtocolTemplates::new();
        let mapping = templates.describe_input_mapping(3, true, 0).unwrap();
        assert_eq!(mapping.description, "传送带运行状态");
    }
}
