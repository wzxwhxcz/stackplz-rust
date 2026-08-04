use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Mutex;

/// DumpWriter writes perf events to a binary file for later replay
/// Format: total_len(u32) | event_index(u8) | rec_type(u32) | rec_len(u32) | rec_raw(bytes)
pub struct DumpWriter {
    file: Mutex<File>,
}

impl DumpWriter {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::create(path).context(format!("failed to create dump file: {}", path))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn write_record(&self, event_index: u8, rec_type: u32, raw_sample: &[u8]) -> Result<()> {
        let rec_len = raw_sample.len() as u32;
        let total_len = 1 + 4 + 4 + rec_len; // event_index(1) + rec_type(4) + rec_len(4) + raw_sample

        let mut file = self.file.lock().unwrap();

        // Write in little-endian format to match Go implementation
        file.write_all(&total_len.to_le_bytes())?;
        file.write_all(&[event_index])?;
        file.write_all(&rec_type.to_le_bytes())?;
        file.write_all(&rec_len.to_le_bytes())?;
        file.write_all(raw_sample)?;

        Ok(())
    }
}

/// DumpReader reads perf events from a binary dump file
pub struct DumpReader {
    file: File,
}

#[derive(Debug)]
pub struct DumpRecord {
    pub event_index: u8,
    pub rec_type: u32,
    pub raw_sample: Vec<u8>,
}

impl DumpReader {
    pub fn new(path: &str) -> Result<Self> {
        let file = File::open(path).context(format!("failed to open dump file: {}", path))?;
        Ok(Self { file })
    }

    pub fn read_record(&mut self) -> Result<Option<DumpRecord>> {
        let mut total_len_buf = [0u8; 4];
        match self.file.read_exact(&mut total_len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let _total_len = u32::from_le_bytes(total_len_buf);

        let mut event_index_buf = [0u8; 1];
        self.file.read_exact(&mut event_index_buf)?;
        let event_index = event_index_buf[0];

        let mut rec_type_buf = [0u8; 4];
        self.file.read_exact(&mut rec_type_buf)?;
        let rec_type = u32::from_le_bytes(rec_type_buf);

        let mut rec_len_buf = [0u8; 4];
        self.file.read_exact(&mut rec_len_buf)?;
        let rec_len = u32::from_le_bytes(rec_len_buf);

        let mut raw_sample = vec![0u8; rec_len as usize];
        self.file.read_exact(&mut raw_sample)?;

        Ok(Some(DumpRecord {
            event_index,
            rec_type,
            raw_sample,
        }))
    }

    pub fn iter(&mut self) -> DumpRecordIterator<'_> {
        DumpRecordIterator { reader: self }
    }
}

pub struct DumpRecordIterator<'a> {
    reader: &'a mut DumpReader,
}

impl<'a> Iterator for DumpRecordIterator<'a> {
    type Item = Result<DumpRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_dump_write_read_roundtrip() -> Result<()> {
        let path = "test_dump.bin";

        // Write some records
        {
            let writer = DumpWriter::new(path)?;
            writer.write_record(1, 0x1234, b"hello")?;
            writer.write_record(2, 0x5678, b"world")?;
            writer.write_record(3, 0xabcd, b"test data")?;
        }

        // Read them back
        {
            let mut reader = DumpReader::new(path)?;

            let rec1 = reader.read_record()?.expect("record 1");
            assert_eq!(rec1.event_index, 1);
            assert_eq!(rec1.rec_type, 0x1234);
            assert_eq!(rec1.raw_sample, b"hello");

            let rec2 = reader.read_record()?.expect("record 2");
            assert_eq!(rec2.event_index, 2);
            assert_eq!(rec2.rec_type, 0x5678);
            assert_eq!(rec2.raw_sample, b"world");

            let rec3 = reader.read_record()?.expect("record 3");
            assert_eq!(rec3.event_index, 3);
            assert_eq!(rec3.rec_type, 0xabcd);
            assert_eq!(rec3.raw_sample, b"test data");

            let rec4 = reader.read_record()?;
            assert!(rec4.is_none());
        }

        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn test_dump_iterator() -> Result<()> {
        let path = "test_dump_iter.bin";

        {
            let writer = DumpWriter::new(path)?;
            writer.write_record(1, 100, b"one")?;
            writer.write_record(2, 200, b"two")?;
            writer.write_record(3, 300, b"three")?;
        }

        {
            let mut reader = DumpReader::new(path)?;
            let records: Vec<_> = reader.iter().collect::<Result<Vec<_>>>()?;

            assert_eq!(records.len(), 3);
            assert_eq!(records[0].event_index, 1);
            assert_eq!(records[1].event_index, 2);
            assert_eq!(records[2].event_index, 3);
        }

        fs::remove_file(path)?;
        Ok(())
    }
}
