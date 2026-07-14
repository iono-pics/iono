use std::io::Cursor;

const FALLBACK_MIME_TYPE: &str = "application/octet-stream";

fn decode_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    limits
}

pub fn detect(bytes: &[u8]) -> String {
    let Some(kind) = infer::get(bytes) else {
        return FALLBACK_MIME_TYPE.to_string();
    };

    let mime = kind.mime_type();

    if is_trusted_image_signature(mime) {
        return if decodes_as_image(bytes) {
            mime.to_string()
        } else {
            FALLBACK_MIME_TYPE.to_string()
        };
    }

    if is_trusted_video_signature(mime) {
        return mime.to_string();
    }

    FALLBACK_MIME_TYPE.to_string()
}

pub fn extension_for(mime_type: &str) -> &'static str {
    match mime_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        _ => "bin",
    }
}

pub fn is_inline_safe(mime_type: &str) -> bool {
    is_trusted_image_signature(mime_type) || is_trusted_video_signature(mime_type)
}

fn decodes_as_image(bytes: &[u8]) -> bool {
    let Ok(mut reader) = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format() else {
        return false;
    };
    reader.limits(decode_limits());
    reader.decode().is_ok()
}

fn is_trusted_image_signature(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

fn is_trusted_video_signature(mime: &str) -> bool {
    matches!(
        mime,
        "video/mp4" | "video/webm" | "video/quicktime" | "video/x-matroska"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_png() {
        let img = image::RgbImage::new(2, 2);
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .unwrap();

        assert_eq!(detect(&bytes), "image/png");
    }

    #[test]
    fn rejects_spoofed_signature() {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);

        assert_eq!(detect(&bytes), FALLBACK_MIME_TYPE);
    }

    #[test]
    fn falls_back_for_unrecognized_bytes() {
        assert_eq!(detect(b"just some plain text"), FALLBACK_MIME_TYPE);
    }
}
