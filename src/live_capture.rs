use crate::protocol_parser::{DiagnosticCode, FrameType, ParsedFrame, ServicePrimitive};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

pub enum CaptureError {
    Io(io::Error),
    Timeout,
    Stopped,
    InvalidConfig(String),
}

impl From<io::Error> for CaptureError {
    fn from(err: io::Error) -> Self {
        CaptureError::Io(err)
    }
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Io(e) => write!(f, "IO 错误: {}", e),
            CaptureError::Timeout => write!(f, "读取超时"),
            CaptureError::Stopped => write!(f, "捕获已停止"),
            CaptureError::InvalidConfig(m) => write!(f, "配置错误: {}", m),
        }
    }
}

impl std::fmt::Debug for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for CaptureError {}

pub trait CaptureSource {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError>;
    fn source_name(&self) -> &str;
    fn set_timeout(&mut self, timeout: Duration) -> Result<(), CaptureError>;
}

pub struct StreamFrameScanner {
    buffer: Vec<u8>,
    start_delimiter: u8,
    last_timestamp: u32,
    start_time: Instant,
    frames_parsed: u64,
    frames_dropped: u64,
}

impl StreamFrameScanner {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            start_delimiter: 0x10,
            last_timestamp: 0,
            start_time: Instant::now(),
            frames_parsed: 0,
            frames_dropped: 0,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.frames_parsed, self.frames_dropped)
    }

    pub fn try_next_frame(&mut self) -> Option<Result<ParsedFrame, CaptureError>> {
        if self.buffer.len() < 6 {
            return None;
        }

        let sd_pos = match self.buffer.iter().position(|&b| b == self.start_delimiter) {
            Some(pos) => pos,
            None => {
                self.buffer.clear();
                return None;
            }
        };

        if sd_pos > 0 {
            self.frames_dropped += sd_pos as u64;
            self.buffer.drain(..sd_pos);
        }

        if self.buffer.len() < 3 {
            return None;
        }

        let frame_len = self.buffer[1] as usize;
        if frame_len < 6 {
            self.buffer.drain(..1);
            return self.try_next_frame();
        }

        if self.buffer.len() < frame_len {
            return None;
        }

        let frame_data = &self.buffer[..frame_len];
        match Self::parse_frame_bytes(frame_data, self.next_timestamp()) {
            Ok(frame) => {
                self.buffer.drain(..frame_len);
                self.frames_parsed += 1;
                Some(Ok(frame))
            }
            Err(_) => {
                self.buffer.drain(..1);
                self.frames_dropped += 1;
                self.try_next_frame()
            }
        }
    }

    fn next_timestamp(&self) -> u32 {
        self.start_time.elapsed().as_millis() as u32
    }

    fn parse_frame_bytes(data: &[u8], timestamp: u32) -> Result<ParsedFrame, ()> {
        if data.len() < 6 {
            return Err(());
        }
        if data[0] != 0x10 {
            return Err(());
        }
        let le = data[1];
        let ler = data[2];
        if le != ler || le as usize != data.len() {
            return Err(());
        }

        let fc = data[3];
        let da = data[4];
        let sa = data[5];

        let pdu = &data[6..data.len().saturating_sub(2)];

        let ed = data[data.len().saturating_sub(1)];
        if ed != 0x16 {
            return Err(());
        }

        let fcs = data[data.len().saturating_sub(2)];
        let computed_fcs = data[4..data.len().saturating_sub(2)]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        if fcs != computed_fcs {
            return Err(());
        }

        let frame_type = Self::decode_frame_type(fc);
        let (fcb, fcv) = ((fc & 0x20) != 0, (fc & 0x10) != 0);
        let (input_data, output_data, service_primitive, diagnostic_data, bus_fault, fault_reason) =
            Self::decode_pdu(pdu, frame_type);

        Ok(ParsedFrame {
            timestamp,
            frame_type,
            service_primitive,
            master_address: sa,
            slave_address: da & 0x7F,
            frame_length: data.len(),
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
            0x04 | 0x05 => FrameType::SrdLow,
            0x06 | 0x07 => FrameType::SrdHigh,
            0x0A => FrameType::Sda,
            0x0E => FrameType::Csf,
            0x0F => FrameType::FdlStatus,
            _ => FrameType::Unknown,
        }
    }

    fn decode_pdu(
        pdu: &[u8],
        frame_type: FrameType,
    ) -> (
        Vec<u8>,
        Vec<u8>,
        ServicePrimitive,
        Vec<DiagnosticCode>,
        bool,
        Option<String>,
    ) {
        let mut input_data = Vec::new();
        let mut output_data = Vec::new();
        let mut diagnostic_codes = Vec::new();
        let mut bus_fault = false;
        let mut fault_reason = None;

        if pdu.is_empty() {
            return (
                input_data,
                output_data,
                ServicePrimitive::Unknown,
                diagnostic_codes,
                bus_fault,
                fault_reason,
            );
        }

        let service_primitive = match pdu[0] {
            0x00..=0x3F => {
                let is_response = matches!(frame_type, FrameType::Csf);
                if is_response && pdu.len() > 1 {
                    input_data = pdu[1..].to_vec();
                } else if pdu.len() > 1 {
                    output_data = pdu[1..].to_vec();
                }
                ServicePrimitive::DataExchange
            }
            0x5E => {
                diagnostic_codes = Self::decode_diagnostic_data(&pdu[1..]);
                if !diagnostic_codes.is_empty() {
                    bus_fault = diagnostic_codes.iter().any(|d| d.code != 0x0000);
                    if bus_fault {
                        fault_reason = diagnostic_codes
                            .iter()
                            .find(|d| d.code != 0x0000)
                            .map(|d| d.description.to_string());
                    }
                }
                ServicePrimitive::SlaveDiagnostic
            }
            0x51 => ServicePrimitive::SetPrm,
            0x52 => ServicePrimitive::ChkCfg,
            0x55 => ServicePrimitive::SetSlaveAdd,
            0x56 => ServicePrimitive::ReadInput,
            0x57 => ServicePrimitive::ReadOutput,
            0x58 => ServicePrimitive::GlobalControl,
            _ => ServicePrimitive::Unknown,
        };

        (
            input_data,
            output_data,
            service_primitive,
            diagnostic_codes,
            bus_fault,
            fault_reason,
        )
    }

    fn decode_diagnostic_data(data: &[u8]) -> Vec<DiagnosticCode> {
        use crate::protocol_parser::ProtocolParser;
        let mut codes = Vec::new();
        if data.is_empty() {
            codes.push(ProtocolParser::lookup_diagnostic_code(0x0000));
            return codes;
        }
        let master_diag = data[0];
        if master_diag != 0 {
            codes.push(ProtocolParser::lookup_diagnostic_code(master_diag as u16));
        }
        if data.len() >= 4 {
            let ident = u16::from_le_bytes([data[2], data[3]]);
            if ident != 0 {
                codes.push(ProtocolParser::lookup_diagnostic_code(ident));
            }
        }
        if codes.is_empty() {
            codes.push(ProtocolParser::lookup_diagnostic_code(0x0000));
        }
        codes
    }
}

impl Default for StreamFrameScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SerialCapture {
    port: Box<dyn serialport::SerialPort>,
    name: String,
}

impl SerialCapture {
    pub fn open(
        path: &str,
        baud_rate: u32,
        timeout: Duration,
    ) -> Result<Self, CaptureError> {
        let port = serialport::new(path, baud_rate)
            .data_bits(serialport::DataBits::Eight)
            .flow_control(serialport::FlowControl::None)
            .parity(serialport::Parity::Even)
            .stop_bits(serialport::StopBits::One)
            .timeout(timeout)
            .open()
            .map_err(|e| CaptureError::InvalidConfig(format!("串口打开失败: {}", e)))?;

        Ok(Self {
            port,
            name: path.to_string(),
        })
    }
}

impl CaptureSource for SerialCapture {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError> {
        self.port
            .read(buf)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::TimedOut {
                    CaptureError::Timeout
                } else {
                    CaptureError::Io(io::Error::new(io::ErrorKind::Other, e))
                }
            })
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<(), CaptureError> {
        self.port
            .set_timeout(timeout)
            .map_err(|e| CaptureError::Io(io::Error::new(io::ErrorKind::Other, e)))
    }
}

pub struct UdpCapture {
    socket: UdpSocket,
    name: String,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
}

impl UdpCapture {
    pub fn bind(addr: &str) -> Result<Self, CaptureError> {
        let socket = UdpSocket::bind(addr).map_err(CaptureError::Io)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(CaptureError::Io)?;
        Ok(Self {
            socket,
            name: format!("udp://{}", addr),
            buf: vec![0u8; 65536],
            pos: 0,
            len: 0,
        })
    }
}

impl CaptureSource for UdpCapture {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError> {
        if self.pos < self.len {
            let available = self.len - self.pos;
            let copy_len = buf.len().min(available);
            buf[..copy_len].copy_from_slice(&self.buf[self.pos..self.pos + copy_len]);
            self.pos += copy_len;
            return Ok(copy_len);
        }

        self.pos = 0;
        self.len = 0;

        match self.socket.recv(&mut self.buf) {
            Ok(n) => {
                self.len = n;
                let copy_len = buf.len().min(n);
                buf[..copy_len].copy_from_slice(&self.buf[..copy_len]);
                self.pos = copy_len;
                Ok(copy_len)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Err(CaptureError::Timeout),
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => Err(CaptureError::Timeout),
            Err(e) => Err(CaptureError::Io(e)),
        }
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<(), CaptureError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(CaptureError::Io)
    }
}

pub struct StdinCapture {
    name: String,
}

impl StdinCapture {
    pub fn new() -> Self {
        Self {
            name: "stdin".to_string(),
        }
    }
}

impl Default for StdinCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureSource for StdinCapture {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError> {
        use std::io::Read;
        std::io::stdin().read(buf).map_err(CaptureError::Io)
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn set_timeout(&mut self, _timeout: Duration) -> Result<(), CaptureError> {
        Ok(())
    }
}

pub struct FileStreamCapture {
    file: File,
    name: String,
    chunk_size: usize,
    simulate_realtime: bool,
    last_read: Instant,
}

impl FileStreamCapture {
    pub fn open<P: AsRef<Path>>(path: P, simulate_realtime: bool) -> Result<Self, CaptureError> {
        let file = File::open(path).map_err(CaptureError::Io)?;
        let name = path.as_ref().display().to_string();
        Ok(Self {
            file,
            name,
            chunk_size: 64,
            simulate_realtime,
            last_read: Instant::now(),
        })
    }

    pub fn set_chunk_size(&mut self, size: usize) {
        self.chunk_size = size.max(1);
    }
}

impl CaptureSource for FileStreamCapture {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CaptureError> {
        if self.simulate_realtime {
            let elapsed = self.last_read.elapsed();
            let frame_interval = Duration::from_millis(20);
            if elapsed < frame_interval {
                std::thread::sleep(frame_interval - elapsed);
            }
            self.last_read = Instant::now();

            let to_read = buf.len().min(self.chunk_size);
            let mut small_buf = vec![0u8; to_read];
            match self.file.read(&mut small_buf) {
                Ok(0) => Err(CaptureError::Stopped),
                Ok(n) => {
                    buf[..n].copy_from_slice(&small_buf[..n]);
                    Ok(n)
                }
                Err(e) => Err(CaptureError::Io(e)),
            }
        } else {
            self.file.read(buf).map_err(CaptureError::Io)
        }
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn set_timeout(&mut self, _timeout: Duration) -> Result<(), CaptureError> {
        Ok(())
    }
}

pub enum LiveSourceType {
    Serial(String, u32),
    Udp(String),
    Stdin,
    File(String, bool),
}

pub fn create_capture_source(
    source_type: LiveSourceType,
    timeout: Duration,
) -> Result<Box<dyn CaptureSource>, CaptureError> {
    match source_type {
        LiveSourceType::Serial(path, baud) => {
            let mut source = SerialCapture::open(&path, baud, timeout)?;
            source.set_timeout(timeout)?;
            Ok(Box::new(source))
        }
        LiveSourceType::Udp(addr) => {
            let mut source = UdpCapture::bind(&addr)?;
            source.set_timeout(timeout)?;
            Ok(Box::new(source))
        }
        LiveSourceType::Stdin => Ok(Box::new(StdinCapture::new())),
        LiveSourceType::File(path, simulate) => {
            let source = FileStreamCapture::open(&path, simulate)?;
            Ok(Box::new(source))
        }
    }
}

pub struct LiveCaptureEngine {
    source: Box<dyn CaptureSource>,
    scanner: StreamFrameScanner,
    read_buf: Vec<u8>,
    running: bool,
    total_bytes: u64,
}

impl LiveCaptureEngine {
    pub fn new(source: Box<dyn CaptureSource>) -> Self {
        Self {
            source,
            scanner: StreamFrameScanner::new(),
            read_buf: vec![0u8; 4096],
            running: true,
            total_bytes: 0,
        }
    }

    pub fn source_name(&self) -> &str {
        self.source.source_name()
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        let (parsed, dropped) = self.scanner.stats();
        (parsed, dropped, self.total_bytes)
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn poll_frame(&mut self) -> Result<Option<ParsedFrame>, CaptureError> {
        if let Some(frame) = self.scanner.try_next_frame() {
            return match frame {
                Ok(f) => Ok(Some(f)),
                Err(_) => Ok(None),
            };
        }

        if !self.running {
            return Err(CaptureError::Stopped);
        }

        match self.source.read(&mut self.read_buf) {
            Ok(0) => Err(CaptureError::Stopped),
            Ok(n) => {
                self.total_bytes += n as u64;
                self.scanner.feed(&self.read_buf[..n]);
                Ok(self.scanner.try_next_frame().and_then(|f| f.ok()))
            }
            Err(CaptureError::Timeout) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_frame(slave: u8, master: u8, fc: u8, pdu: &[u8]) -> Vec<u8> {
        let total_len: u8 = (6 + pdu.len() + 2) as u8;
        let mut frame = vec![0x10, total_len, total_len, fc, slave, master];
        frame.extend_from_slice(pdu);
        let fcs = frame[4..frame.len()].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        frame.push(fcs);
        frame.push(0x16);
        frame
    }

    #[test]
    fn test_stream_scanner_single_frame() {
        let mut scanner = StreamFrameScanner::new();
        let frame = build_test_frame(3, 1, 0xF7, &[0x00, 0x01, 0x02]);
        scanner.feed(&frame);
        let result = scanner.try_next_frame();
        assert!(result.is_some());
        let frame = result.unwrap().unwrap();
        assert_eq!(frame.slave_address, 3);
        assert_eq!(frame.master_address, 1);
    }

    #[test]
    fn test_stream_scanner_partial_feed() {
        let mut scanner = StreamFrameScanner::new();
        let frame = build_test_frame(5, 2, 0xF4, &[0x00, 0xAA, 0xBB]);

        scanner.feed(&frame[..5]);
        assert!(scanner.try_next_frame().is_none());

        scanner.feed(&frame[5..]);
        let result = scanner.try_next_frame();
        assert!(result.is_some());
        let parsed = result.unwrap().unwrap();
        assert_eq!(parsed.slave_address, 5);
    }

    #[test]
    fn test_stream_scanner_multiple_frames() {
        let mut scanner = StreamFrameScanner::new();
        let f1 = build_test_frame(3, 1, 0xF7, &[0x00, 0x11]);
        let f2 = build_test_frame(7, 1, 0xF4, &[0x00, 0x22, 0x33]);

        let mut combined = Vec::new();
        combined.extend_from_slice(&f1);
        combined.extend_from_slice(&f2);
        scanner.feed(&combined);

        let r1 = scanner.try_next_frame();
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().unwrap().slave_address, 3);

        let r2 = scanner.try_next_frame();
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().unwrap().slave_address, 7);
    }

    #[test]
    fn test_stream_scanner_with_junk_before_sd() {
        let mut scanner = StreamFrameScanner::new();
        let frame = build_test_frame(3, 1, 0xF7, &[0x00, 0x01]);
        let mut data = vec![0xAB, 0xCD, 0xEF];
        data.extend_from_slice(&frame);

        scanner.feed(&data);
        let result = scanner.try_next_frame();
        assert!(result.is_some());
        assert_eq!(result.unwrap().unwrap().slave_address, 3);
    }

    #[test]
    fn test_stream_scanner_diagnostic_frame() {
        let mut scanner = StreamFrameScanner::new();
        let pdu = vec![0x5E, 0x05, 0x00, 0x04, 0x00, 0x00];
        let frame = build_test_frame(5, 1, 0xF7, &pdu);

        scanner.feed(&frame);
        let result = scanner.try_next_frame();
        assert!(result.is_some());
        let parsed = result.unwrap().unwrap();
        assert_eq!(parsed.service_primitive, ServicePrimitive::SlaveDiagnostic);
        assert!(parsed.bus_fault);
        assert!(!parsed.diagnostic_data.is_empty());
    }

    #[test]
    fn test_file_stream_capture() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("profibus_test_capture.bin");
        let mut file = File::create(&path).unwrap();
        let frame = build_test_frame(3, 1, 0xF7, &[0x00, 0x01, 0x02]);
        file.write_all(&frame).unwrap();
        drop(file);

        let source = FileStreamCapture::open(&path, false).unwrap();
        let mut engine = LiveCaptureEngine::new(Box::new(source));
        let mut frames = Vec::new();
        loop {
            match engine.poll_frame() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => continue,
                Err(CaptureError::Stopped) => break,
                Err(_) => break,
            }
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].slave_address, 3);

        std::fs::remove_file(&path).ok();
    }
}
