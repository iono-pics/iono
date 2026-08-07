use std::io::Cursor;

use image::codecs::png::{CompressionType, FilterType, PngEncoder};

use crate::content_type;

pub fn recompress(bytes: &[u8], mime_type: &str) -> Option<Vec<u8>> {
    if mime_type != "image/png" || is_animated_png(bytes) {
        return None;
    }

    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    reader.limits(content_type::decode_limits());
    let decoded = reader.decode().ok()?;

    let mut out = Vec::with_capacity(bytes.len());
    decoded
        .write_with_encoder(PngEncoder::new_with_quality(
            &mut out,
            CompressionType::Best,
            FilterType::Adaptive,
        ))
        .ok()?;

    (out.len() < bytes.len()).then_some(out)
}

fn is_animated_png(bytes: &[u8]) -> bool {
    let Some(mut rest) = bytes.get(8..) else {
        return false;
    };

    loop {
        let Some((header, body)) = rest.split_at_checked(8) else {
            return false;
        };

        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        match &header[4..8] {
            b"acTL" => return true,
            // acTL is required before the first IDAT
            b"IDAT" | b"IEND" => return false,
            _ => {}
        }

        let Some(next) = length.checked_add(4).and_then(|skip| body.get(skip..)) else {
            return false;
        };
        rest = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(side: u32, compression: CompressionType) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(side, side, image::Rgb([17, 99, 240]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_with_encoder(PngEncoder::new_with_quality(
                &mut bytes,
                compression,
                FilterType::NoFilter,
            ))
            .unwrap();
        bytes
    }

    fn decode(bytes: &[u8]) -> image::RgbaImage {
        image::load_from_memory(bytes).unwrap().to_rgba8()
    }

    #[test]
    fn shrinks_a_lazily_encoded_png() {
        let original = png(256, CompressionType::Fast);

        let smaller = recompress(&original, "image/png").expect("a fast-encoded png must shrink");

        assert!(
            smaller.len() < original.len(),
            "{} was not smaller than {}",
            smaller.len(),
            original.len()
        );
    }

    #[test]
    fn every_pixel_survives() {
        let original = png(64, CompressionType::Fast);

        let smaller = recompress(&original, "image/png").unwrap();

        assert_eq!(
            decode(&smaller),
            decode(&original),
            "the recompressed image is not pixel-identical"
        );
    }

    #[test]
    fn leaves_an_already_tight_png_alone() {
        let original = png(256, CompressionType::Best);

        assert!(
            recompress(&original, "image/png").is_none(),
            "an already-optimal png must not be replaced by a larger one"
        );
    }

    #[test]
    fn skips_formats_that_cannot_win() {
        let original = png(64, CompressionType::Fast);

        for mime in ["image/jpeg", "image/gif", "image/webp", "video/mp4"] {
            assert!(
                recompress(&original, mime).is_none(),
                "{mime} must not be re-encoded"
            );
        }
    }

    #[test]
    fn skips_apng() {
        let mut apng = png(64, CompressionType::Fast);
        let signature = 8;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&0u32.to_be_bytes());
        chunk.extend_from_slice(b"acTL");
        chunk.extend_from_slice(&0u32.to_be_bytes());
        apng.splice(signature..signature, chunk);

        assert!(is_animated_png(&apng), "the acTL chunk was not spotted");
        assert!(
            recompress(&apng, "image/png").is_none(),
            "an apng must not be flattened to one frame"
        );
    }

    #[test]
    fn survives_truncated_and_junk_input() {
        let original = png(32, CompressionType::Fast);

        assert!(!is_animated_png(&[]));
        assert!(!is_animated_png(&original[..12]));
        assert!(!is_animated_png(&[0xFF; 64]));
        assert!(recompress(&original[..original.len() / 2], "image/png").is_none());
    }
}
