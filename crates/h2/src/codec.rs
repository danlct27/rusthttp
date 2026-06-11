//! HTTP/2 frame codec — read/write typed frames over AsyncRead/AsyncWrite.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::{Frame, FrameHeader, FRAME_HEADER_SIZE};
use crate::H2Error;

/// Read a single HTTP/2 frame from an async reader.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, H2Error> {
    let mut header_buf = [0u8; FRAME_HEADER_SIZE];
    reader.read_exact(&mut header_buf).await?;
    let header = FrameHeader::decode(&header_buf);

    let mut payload_buf = vec![0u8; header.length as usize];
    if header.length > 0 {
        reader.read_exact(&mut payload_buf).await?;
    }
    let payload = Bytes::from(payload_buf);

    Frame::decode(header, payload)
}

/// Write a single HTTP/2 frame to an async writer.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), H2Error> {
    let mut buf = BytesMut::with_capacity(256);
    frame.encode(&mut buf);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Write raw bytes (pre-encoded frame) to an async writer.
pub async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &[u8],
) -> Result<(), H2Error> {
    writer.write_all(buf).await?;
    Ok(())
}
