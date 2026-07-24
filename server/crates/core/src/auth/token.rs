use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};

use crate::entities::DisplayNameStyle;

const NORMAL_ALPHABET: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
];

const EMOJI_ALPHABET: &[char] = &[
    '😀', '😁', '😂', '🤣', '😊', '😍', '😎', '🤩', '🥳', '😴', '🤔', '🙄', '😱', '🥶', '🥵', '👻',
    '🤖', '👽', '🎃', '🐶', '🐱', '🦊', '🐼', '🦁', '🐸', '🐵', '🍕', '🍔', '🍟', '🌮', '🍩', '🍦',
    '🚀', '⭐', '🔥', '💎', '🎉', '🎈', '🌈', '⚡', '🍀', '🎵', '🎶',
];

const ACCENTS_ALPHABET: &[char] = &[
    'à', 'á', 'â', 'ã', 'ä', 'å', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ò', 'ó', 'ô', 'õ', 'ö',
    'ù', 'ú', 'û', 'ü', 'ý', 'ÿ', 'ñ', 'ç', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'È', 'É', 'Ê', 'Ë', 'Ì',
    'Í', 'Î', 'Ï', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Ñ', 'Ç',
];

const INVISIBLE_ALPHABET: &[char] = &[
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{180E}', '\u{2061}', '\u{2062}',
    '\u{2063}', '\u{2064}',
];

pub const API_KEY_PREFIX: &str = "iono_";

pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{API_KEY_PREFIX}{}", hex::encode(bytes))
}

pub fn generate_display_name(length: usize, style: &DisplayNameStyle) -> String {
    let alphabet: &[char] = match style {
        DisplayNameStyle::Normal => NORMAL_ALPHABET,
        DisplayNameStyle::Emoji => EMOJI_ALPHABET,
        DisplayNameStyle::Accents => ACCENTS_ALPHABET,
        DisplayNameStyle::Invisible => INVISIBLE_ALPHABET,
    };
    let mut rng = rand::rng();
    (0..length)
        .map(|_| alphabet[rng.random_range(0..alphabet.len())])
        .collect()
}

pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

pub fn hash_api_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_consistent() {
        let token = generate_api_token();
        assert_eq!(hash_api_token(&token), hash_api_token(&token));
    }

    #[test]
    fn hashes_are_different() {
        assert_ne!(
            hash_api_token(&generate_api_token()),
            hash_api_token(&generate_api_token())
        );
    }

    #[test]
    fn tokens_have_prefix() {
        assert!(generate_api_token().starts_with("iono_"));
    }

    #[test]
    fn display_names_have_requested_length() {
        assert_eq!(
            generate_display_name(16, &DisplayNameStyle::Normal)
                .chars()
                .count(),
            16
        );
        assert_eq!(
            generate_display_name(32, &DisplayNameStyle::Emoji)
                .chars()
                .count(),
            32
        );
    }

    #[test]
    fn normal_style_is_alphanumeric() {
        assert!(generate_display_name(32, &DisplayNameStyle::Normal)
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn each_style_only_uses_its_own_alphabet() {
        for (style, alphabet) in [
            (DisplayNameStyle::Normal, NORMAL_ALPHABET),
            (DisplayNameStyle::Emoji, EMOJI_ALPHABET),
            (DisplayNameStyle::Accents, ACCENTS_ALPHABET),
            (DisplayNameStyle::Invisible, INVISIBLE_ALPHABET),
        ] {
            assert!(generate_display_name(32, &style)
                .chars()
                .all(|c| alphabet.contains(&c)));
        }
    }

    #[test]
    fn recovery_codes_match_expected_format() {
        let code = generate_recovery_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts
            .iter()
            .all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_hexdigit())));
    }

    #[test]
    fn recovery_codes_are_different() {
        assert_ne!(generate_recovery_code(), generate_recovery_code());
    }

    #[test]
    fn display_names_are_different() {
        assert_ne!(
            generate_display_name(16, &DisplayNameStyle::Normal),
            generate_display_name(16, &DisplayNameStyle::Normal)
        );
    }
}
