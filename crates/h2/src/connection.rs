//! HTTP/2 connection lifecycle — preface, settings exchange, request sending.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{read_frame, write_frame};
use crate::frame::{
    encode_chrome_settings, encode_chrome_window_update, encode_ping_ack, encode_settings_ack,
    Frame, CONNECTION_PREFACE,
};
use crate::hpack::{HpackDecoder, HpackEncoder};
use crate::stream::{Stream, StreamIdAllocator};
use crate::H2Error;

/// An HTTP/2 response.
#[derive(Debug)]
pub struct Response {
    /// Response headers (including pseudo-headers like :status).
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Bytes,
}

/// HTTP/2 client connection.
pub struct Connection<T> {
    io: T,
    stream_ids: StreamIdAllocator,
    /// Connection-level send window.
    pub send_window: i32,
    /// Connection-level recv window.
    pub recv_window: i32,
    /// Active streams.
    streams: Vec<Stream>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    /// Perform the HTTP/2 handshake: send preface + SETTINGS + WINDOW_UPDATE,
    /// then read server SETTINGS and ACK it.
    pub async fn handshake(mut io: T) -> Result<Self, H2Error> {
        // Send connection preface
        io.write_all(CONNECTION_PREFACE).await?;

        // Send SETTINGS (Chrome's 4 params in exact order)
        let mut buf = BytesMut::with_capacity(64);
        encode_chrome_settings(&mut buf);
        // Send WINDOW_UPDATE on stream 0 immediately after SETTINGS
        encode_chrome_window_update(&mut buf);
        io.write_all(&buf).await?;
        io.flush().await?;

        let initial_window = crate::chrome::INITIAL_WINDOW_SIZE as i32;
        let conn_window = initial_window + crate::chrome::CONNECTION_WINDOW_INCREMENT as i32;

        let mut conn = Connection {
            io,
            stream_ids: StreamIdAllocator::new(),
            send_window: conn_window,
            recv_window: conn_window,
            streams: Vec::new(),
        };

        // Read server SETTINGS and ACK it
        conn.read_and_ack_settings().await?;

        Ok(conn)
    }

    /// Read frames until we get the server's SETTINGS, then send ACK.
    async fn read_and_ack_settings(&mut self) -> Result<(), H2Error> {
        loop {
            let frame = read_frame(&mut self.io).await?;
            match frame {
                Frame::Settings { ack: false, .. } => {
                    let mut buf = BytesMut::with_capacity(16);
                    encode_settings_ack(&mut buf);
                    self.io.write_all(&buf).await?;
                    self.io.flush().await?;
                    return Ok(());
                }
                Frame::Settings { ack: true, .. } => {
                    // Server ACK'd our settings — continue waiting for theirs
                }
                _ => {
                    self.handle_frame(frame).await?;
                }
            }
        }
    }

    /// Handle a non-SETTINGS frame during connection setup or request.
    async fn handle_frame(&mut self, frame: Frame) -> Result<(), H2Error> {
        match frame {
            Frame::Ping { ack: false, payload } => {
                let mut buf = BytesMut::with_capacity(20);
                encode_ping_ack(&mut buf, payload);
                self.io.write_all(&buf).await?;
                self.io.flush().await?;
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                ..
            } => {
                return Err(H2Error::GoAway {
                    last_stream_id,
                    error_code,
                });
            }
            Frame::WindowUpdate { stream_id: 0, increment } => {
                self.send_window += increment as i32;
            }
            _ => { /* ignore other frames during handshake */ }
        }
        Ok(())
    }

    /// Send an HTTP request and read the response.
    ///
    /// `encoder` / `decoder`: HPACK codec (caller provides).
    /// Headers should include pseudo-headers in Chrome order:
    /// `:method`, `:authority`, `:scheme`, `:path`.
    pub async fn send_request(
        &mut self,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        encoder: &mut impl HpackEncoder,
        decoder: &mut impl HpackDecoder,
    ) -> Result<Response, H2Error> {
        let stream_id = self.stream_ids.next_id();
        let end_stream = body.is_none();

        // Encode HEADERS frame
        let hpack_block = encoder.encode(headers);
        let headers_frame = Frame::Headers {
            stream_id,
            end_stream,
            end_headers: true,
            payload: Bytes::from(hpack_block),
        };
        write_frame(&mut self.io, &headers_frame).await?;

        // Send DATA if body present
        if let Some(data) = body {
            let data_frame = Frame::Data {
                stream_id,
                end_stream: true,
                payload: Bytes::copy_from_slice(data),
            };
            write_frame(&mut self.io, &data_frame).await?;
        }
        self.io.flush().await?;

        // Track stream
        let mut stream = Stream::new(stream_id, crate::chrome::INITIAL_WINDOW_SIZE);
        stream.send_end_stream()?;

        // Read response
        let mut resp_headers = Vec::new();
        let mut resp_body = BytesMut::new();

        loop {
            let frame = read_frame(&mut self.io).await?;
            match frame {
                Frame::Headers {
                    stream_id: sid,
                    end_stream: es,
                    payload,
                    ..
                } if sid == stream_id => {
                    resp_headers = decoder.decode(&payload)?;
                    if es {
                        stream.recv_end_stream()?;
                        break;
                    }
                }
                Frame::Data {
                    stream_id: sid,
                    end_stream: es,
                    payload,
                } if sid == stream_id => {
                    resp_body.extend_from_slice(&payload);
                    if es {
                        stream.recv_end_stream()?;
                        break;
                    }
                }
                Frame::RstStream {
                    stream_id: sid,
                    error_code,
                } if sid == stream_id => {
                    return Err(H2Error::StreamReset {
                        stream_id: sid,
                        error_code,
                    });
                }
                other => {
                    self.handle_frame(other).await?;
                }
            }
        }

        self.streams.push(stream);

        Ok(Response {
            headers: resp_headers,
            body: resp_body.freeze(),
        })
    }
}
