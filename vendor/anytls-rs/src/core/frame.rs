#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

pub const HEADER_OVERHEAD_SIZE: usize = 1 + 4 + 2;
pub const MAX_FRAME_DATA_SIZE: usize = u16::MAX as usize;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Push = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl TryFrom<u8> for Command {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Waste),
            1 => Ok(Self::Syn),
            2 => Ok(Self::Push),
            3 => Ok(Self::Fin),
            4 => Ok(Self::Settings),
            5 => Ok(Self::Alert),
            6 => Ok(Self::UpdatePaddingScheme),
            7 => Ok(Self::SynAck),
            8 => Ok(Self::HeartRequest),
            9 => Ok(Self::HeartResponse),
            10 => Ok(Self::ServerSettings),
            other => Err(other),
        }
    }
}

impl Command {
    pub fn valid_stream_id(self, stream_id: u32) -> bool {
        match self {
            Command::Syn | Command::Push | Command::Fin | Command::SynAck => stream_id > 0,
            Command::Waste | Command::Settings | Command::Alert | Command::UpdatePaddingScheme | Command::ServerSettings => stream_id == 0,
            Command::HeartRequest | Command::HeartResponse => stream_id == 0,
        }
    }

    pub fn allows_data(self) -> bool {
        matches!(
            self,
            Self::Waste | Self::Push | Self::Settings | Self::Alert | Self::UpdatePaddingScheme | Self::SynAck | Self::ServerSettings
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub command: Command,
    pub stream_id: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(command: Command, stream_id: u32) -> Self {
        Self {
            command,
            stream_id,
            data: Vec::new(),
        }
    }

    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        Self::encode_parts(self.command, self.stream_id, &self.data)
    }

    pub(crate) fn encode_parts(command: Command, stream_id: u32, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::{Error, ErrorKind::InvalidInput};
        if data.len() > MAX_FRAME_DATA_SIZE {
            return Err(Error::new(InvalidInput, "frame data exceeds u16"));
        }
        let mut encoded = Vec::with_capacity(HEADER_OVERHEAD_SIZE + data.len());
        encoded.push(command as u8);
        encoded.extend_from_slice(&stream_id.to_be_bytes());
        encoded.extend_from_slice(&(data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(data);
        Ok(encoded)
    }

    #[cfg(feature = "async")]
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind::UnexpectedEof};
        Self::read_from_or_eof(reader)
            .await?
            .ok_or_else(|| Error::new(UnexpectedEof, "stream ended before frame"))
    }

    #[cfg(feature = "async")]
    pub(crate) async fn read_from_or_eof<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Self>> {
        use std::io::{Error, ErrorKind::InvalidData};
        let mut header = [0u8; HEADER_OVERHEAD_SIZE];
        if reader.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut header[1..]).await?;
        let command = Command::try_from(header[0]).map_err(|value| Error::new(InvalidData, format!("unknown command {value}")))?;
        let stream_id = u32::from_be_bytes(
            header[1..5]
                .try_into()
                .map_err(|e| Error::new(InvalidData, format!("invalid header width: {e}")))?,
        );
        let data_len = u16::from_be_bytes(
            header[5..7]
                .try_into()
                .map_err(|e| Error::new(InvalidData, format!("invalid header width: {e}")))?,
        ) as usize;
        let mut data = vec![0u8; data_len];
        reader.read_exact(&mut data).await?;
        Ok(Some(Self { command, stream_id, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "async")]
    use tokio::io::BufReader;

    #[test]
    fn encodes_empty_frame() {
        let frame = Frame::new(Command::Syn, 0x0102_0304);
        assert_eq!(frame.encode().unwrap(), [1, 1, 2, 3, 4, 0, 0]);
    }

    #[test]
    fn encodes_go_compatible_big_endian_frame() {
        let mut frame = Frame::new(Command::Push, 0x0102_0304);
        frame.data = b"hello".to_vec();
        let bytes = frame.encode().unwrap();
        assert_eq!(&bytes[..], &[2, 1, 2, 3, 4, 0, 5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn encodes_maximum_frame_payload() {
        let mut frame = Frame::new(Command::Push, 0x0102_0304);
        frame.data = (0..65_535).map(|index| index as u8).collect();
        let bytes = frame.encode().unwrap();
        assert_eq!(&bytes[..7], &[2, 1, 2, 3, 4, 0xff, 0xff]);
        assert_eq!(&bytes[7..], frame.data.as_slice());
    }

    #[test]
    fn rejects_oversized_frame_payload() {
        let mut frame = Frame::new(Command::Push, 1);
        frame.data = vec![0; 65_536];
        assert_eq!(frame.encode().unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn reads_go_compatible_big_endian_frame() {
        let mut frame = Frame::new(Command::Push, 0x0102_0304);
        frame.data = b"hello".to_vec();
        let bytes = frame.encode().unwrap();
        assert_eq!(Frame::read_from(&mut BufReader::new(bytes.as_slice())).await.unwrap(), frame);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn distinguishes_frame_boundary_eof_from_truncated_frames() {
        let mut empty = &[][..];
        assert!(Frame::read_from_or_eof(&mut empty).await.unwrap().is_none());

        let truncated_header = [Command::Push as u8, 0];
        let mut input = truncated_header.as_slice();
        assert_eq!(
            Frame::read_from_or_eof(&mut input).await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        let truncated_payload = [Command::Push as u8, 0, 0, 0, 1, 0, 2, b'x'];
        let mut input = truncated_payload.as_slice();
        assert_eq!(
            Frame::read_from_or_eof(&mut input).await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
