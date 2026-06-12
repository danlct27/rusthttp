//! HTTP/2 connection lifecycle — preface, settings exchange, request sending.

use bytes::{Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::codec::{read_frame_with_max, write_frame};
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
    /// Max frame size the peer accepts (from their SETTINGS).
    peer_max_frame_size: u32,
    /// If GOAWAY received, the last stream ID the server will process.
    goaway_last_stream_id: Option<u32>,
    /// Max response body size (default 100MB).
    max_response_body_size: usize,
    /// Read timeout for response frames (guards against GOAWAY-then-silence).
    response_timeout: Duration,
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

        // Connection-level window: RFC default 65535 + our WINDOW_UPDATE increment
        // (SETTINGS_INITIAL_WINDOW_SIZE only applies to streams, not connection)
        let conn_window = 65535 + crate::chrome::CONNECTION_WINDOW_INCREMENT as i32;

        let mut conn = Connection {
            io,
            stream_ids: StreamIdAllocator::new(),
            // Our send_window starts at RFC default (server may update via their WINDOW_UPDATE)
            send_window: 65535,
            recv_window: conn_window,
            peer_max_frame_size: 16_384,
            goaway_last_stream_id: None,
            max_response_body_size: 100 * 1024 * 1024, // 100MB
            response_timeout: Duration::from_secs(30),
        };

        // Read server SETTINGS and ACK it
        conn.read_and_ack_settings().await?;

        Ok(conn)
    }

    /// Read frames until we get the server's SETTINGS, then send ACK.
    async fn read_and_ack_settings(&mut self) -> Result<(), H2Error> {
        // SETTINGS/GOAWAY frames should never exceed 64KB — cap to prevent DoS
        const HANDSHAKE_FRAME_CAP: u32 = 65536;
        loop {
            let frame = read_frame_with_max(&mut self.io, HANDSHAKE_FRAME_CAP).await?;
            match frame {
                Frame::Settings { ack: false, ref params } => {
                    // Track server's settings
                    for &(id, val) in params {
                        if id == 0x5 && (16_384..=16_777_215).contains(&val) {
                            self.peer_max_frame_size = val;
                        }
                    }
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
                // Store GOAWAY — don't abort immediately; let in-flight streams finish
                self.goaway_last_stream_id = Some(last_stream_id);
                // If error_code != 0 (NO_ERROR), it's a real error
                if error_code != 0 {
                    return Err(H2Error::GoAway {
                        last_stream_id,
                        error_code,
                    });
                }
            }
            Frame::WindowUpdate { stream_id: 0, increment } => {
                // Check for flow control overflow (RFC 7540 §6.9.1)
                let new_window = (self.send_window as i64) + (increment as i64);
                if new_window > 0x7FFF_FFFF {
                    return Err(H2Error::Protocol(
                        "flow control window overflow".into(),
                    ));
                }
                self.send_window = new_window as i32;
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
        // Check if GOAWAY received — reject new requests
        if let Some(last_id) = self.goaway_last_stream_id {
            let next = self.stream_ids.peek();
            if next > last_id {
                return Err(H2Error::GoAway {
                    last_stream_id: last_id,
                    error_code: 0,
                });
            }
        }

        let stream_id = self.stream_ids.next_id()?;
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

        // Send DATA if body present — chunk to peer_max_frame_size
        if let Some(data) = body {
            let max = self.peer_max_frame_size as usize;
            let chunks: Vec<&[u8]> = data.chunks(max).collect();
            let last_idx = chunks.len().saturating_sub(1);
            for (i, chunk) in chunks.iter().enumerate() {
                let data_frame = Frame::Data {
                    stream_id,
                    end_stream: i == last_idx,
                    payload: Bytes::copy_from_slice(chunk),
                };
                write_frame(&mut self.io, &data_frame).await?;
            }
        }
        self.io.flush().await?;

        // Track stream
        let mut stream = Stream::new(stream_id, crate::chrome::INITIAL_WINDOW_SIZE);
        stream.send_end_stream()?;

        // Read response (with timeout guard against GOAWAY-then-silence)
        let mut resp_headers = Vec::new();
        let mut resp_body = BytesMut::new();

        loop {
            let frame = timeout(self.response_timeout, read_frame_with_max(&mut self.io, self.peer_max_frame_size))
                .await
                .map_err(|_| H2Error::Protocol("response read timeout".into()))??;
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
                    ref payload,
                } if sid == stream_id => {
                    // Decrement connection + stream recv window
                    let len = payload.len() as i32;
                    self.recv_window -= len;
                    stream.recv_window -= len;

                    resp_body.extend_from_slice(payload);

                    // Guard against unbounded response body
                    if resp_body.len() > self.max_response_body_size {
                        return Err(H2Error::Protocol("response body exceeds max size".into()));
                    }

                    // Send connection-level WINDOW_UPDATE when unacked bytes exceed half
                    // (matches Chrome's IncreaseRecvWindowSize behavior)
                    let conn_max = 65535_i32 + crate::chrome::CONNECTION_WINDOW_INCREMENT as i32;
                    let unacked = conn_max - self.recv_window;
                    if unacked > conn_max / 2 {
                        let wu = Frame::WindowUpdate { stream_id: 0, increment: unacked as u32 };
                        write_frame(&mut self.io, &wu).await?;
                        self.recv_window += unacked;
                    }

                    // Send stream-level WINDOW_UPDATE when stream window depleted past half
                    let stream_initial = crate::chrome::INITIAL_WINDOW_SIZE as i32;
                    let stream_unacked = stream_initial - stream.recv_window;
                    if stream_unacked > stream_initial / 2 {
                        let swu = Frame::WindowUpdate { stream_id, increment: stream_unacked as u32 };
                        write_frame(&mut self.io, &swu).await?;
                        stream.recv_window += stream_unacked;
                    }

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

        Ok(Response {
            headers: resp_headers,
            body: resp_body.freeze(),
        })
    }
}
