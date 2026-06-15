use std::fs::File;
use std::io::{self, Read, stdin};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSource {
    File(String),
    Stdin,
}

#[derive(Debug)]
pub struct PacketReader {
    source: DataSource,
    buffer: Vec<u8>,
    position: usize,
}

impl PacketReader {
    pub fn new(source: DataSource) -> io::Result<Self> {
        let buffer = match &source {
            DataSource::File(path) => {
                let mut file = File::open(Path::new(path))?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                buffer
            }
            DataSource::Stdin => {
                let mut buffer = Vec::new();
                stdin().read_to_end(&mut buffer)?;
                buffer
            }
        };

        Ok(Self {
            source,
            buffer,
            position: 0,
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::new(DataSource::File(path.as_ref().to_string_lossy().into_owned())
    }

    pub fn from_stdin() -> io::Result<Self> {
        Self::new(DataSource::Stdin)
    }

    pub fn read_bytes(&mut self, count: usize) -> io::Result<&[u8]> {
        if self.position + count > self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected end of packet stream",
            ));
        }
        let start = self.position;
        self.position += count;
        Ok(&self.buffer[start..self.position])
    }

    pub fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_u16_le(&mut self) -> io::Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u16_be(&mut self) -> io::Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32_le(&mut self) -> io::Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u32_be(&mut self) -> io::Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn total_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_eof(&self) -> bool {
        self.position >= self.buffer.len()
    }

    pub fn seek(&mut self, pos: usize) -> io::Result<()> {
        if pos > self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek position out of bounds",
            ));
        }
        self.position = pos;
        Ok(())
    }

    pub fn peek(&self, offset: usize, count: usize) -> io::Result<&[u8]> {
        if self.position + offset + count > self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Peek position out of bounds",
            ));
        }
        let start = self.position + offset;
        Ok(&self.buffer[start..start + count])
    }

    pub fn source(&self) -> &DataSource {
        &self.source
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_packet_reader_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.as_file()
            .write_all(&[0x01, 0x02, 0x03, 0x04])
            .unwrap();
        let path = file.path().to_path_buf();

        let mut reader = PacketReader::from_file(&path).unwrap();
        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.read_u8().unwrap(), 0x02);
        assert_eq!(reader.remaining(), 2);
    }

    #[test]
    fn test_packet_reader_endianness() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = PacketReader {
            source: DataSource::Stdin,
            buffer: data,
            position: 0,
        };
        assert_eq!(reader.read_u16_le().unwrap(), 0x0201);
        assert_eq!(reader.read_u16_be().unwrap(), 0x0304);
    }

    #[test]
    fn test_packet_reader_seek_peek() {
        let data = vec![0x10, 0x20, 0x30, 0x40];
        let mut reader = PacketReader {
            source: DataSource::Stdin,
            buffer: data,
            position: 0,
        };
        assert_eq!(reader.peek(2, 1).unwrap(), &[0x30]);
        reader.seek(2).unwrap();
        assert_eq!(reader.read_u8().unwrap(), 0x30);
    }
}
