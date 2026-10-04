use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn read_frame<S>(stream: &mut S) -> anyhow::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0u8; 4];

    match timeout(FRAME_TIMEOUT, stream.read_exact(&mut length)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(anyhow::anyhow!("control frame header timeout")),
    }

    let length = u32::from_be_bytes(length) as usize;

    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(anyhow::anyhow!(
            "control frame exceeds the configured bound"
        ));
    }

    let mut frame = vec![0u8; length];

    timeout(FRAME_TIMEOUT, stream.read_exact(&mut frame))
        .await
        .map_err(|_| anyhow::anyhow!("control frame timeout"))??;

    Ok(Some(frame))
}

pub(super) async fn write_frame<S>(stream: &mut S, payload: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(anyhow::anyhow!(
            "control response exceeds the configured bound"
        ));
    }

    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;

    stream.write_all(payload).await?;

    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::{read_frame, write_frame};

    #[tokio::test]
    async fn frames_round_trip_at_both_size_bounds_with_big_endian_headers() {
        // Peer wire fixtures must not follow changes to the gateway's size limit or encoder.
        for (length, header) in [
            (1, [0x00, 0x00, 0x00, 0x01]),
            (4_194_304, [0x00, 0x40, 0x00, 0x00]),
        ] {
            let payload = vec![0xa5; length];

            let mut expected_wire = header.to_vec();

            expected_wire.extend_from_slice(&payload);

            let mut wire = Vec::new();

            write_frame(&mut wire, &payload).await.unwrap();

            assert_eq!(wire, expected_wire);

            let mut reader = expected_wire.as_slice();

            assert_eq!(read_frame(&mut reader).await.unwrap(), Some(payload));

            assert!(read_frame(&mut reader).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn consecutive_frames_remain_separate() {
        let mut wire = Vec::new();

        write_frame(&mut wire, b"first").await.unwrap();

        write_frame(&mut wire, b"second").await.unwrap();

        let mut reader = wire.as_slice();

        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Some(b"first".to_vec())
        );

        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Some(b"second".to_vec())
        );

        assert!(read_frame(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_zero_and_oversized_lengths_before_reading_payload() {
        for header in [
            [0x00, 0x00, 0x00, 0x00],
            [0x00, 0x40, 0x00, 0x01],
            [0xff, 0xff, 0xff, 0xff],
        ] {
            let mut reader = header.as_slice();

            let error = read_frame(&mut reader).await.unwrap_err();

            assert_eq!(
                error.to_string(),
                "control frame exceeds the configured bound"
            );
        }
    }

    #[tokio::test]
    async fn write_frame_rejects_empty_and_oversized_payloads_without_writing() {
        for length in [0, 4_194_305] {
            let payload = vec![0xa5; length];

            let mut wire = b"unchanged".to_vec();

            let error = write_frame(&mut wire, &payload).await.unwrap_err();

            assert_eq!(
                error.to_string(),
                "control response exceeds the configured bound"
            );

            assert_eq!(wire, b"unchanged");
        }
    }

    #[tokio::test]
    async fn missing_or_partial_headers_are_end_of_stream() {
        let header = [0x00, 0x00, 0x00, 0x01];

        for length in 0..header.len() {
            let mut reader = &header[..length];

            assert!(read_frame(&mut reader).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn truncated_payload_is_an_error_not_end_of_stream() {
        let wire = [0, 0, 0, 2, 0xa5];

        let mut reader = wire.as_slice();

        let error = read_frame(&mut reader).await.unwrap_err();

        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
