use humansize::{format_size, FormatSizeOptions, WINDOWS};
use iono_core::entities::{EmbedPreset, File};
use maud::{html, PreEscaped, DOCTYPE};

const DEFAULT_SITE_NAME: &str = "iono";
const DEFAULT_COLOR: &str = "#7c3aed";

pub fn render_embed_html(file: &File, raw_url: &str, preset: Option<&EmbedPreset>) -> String {
    let title = preset
        .and_then(|p| p.title.as_deref())
        .unwrap_or(&file.display_name);
    let description = preset.and_then(|p| p.description.as_deref()).unwrap_or("");
    let site_name = preset
        .and_then(|p| p.site_name.as_deref())
        .unwrap_or(DEFAULT_SITE_NAME);
    let color = sanitize_color(
        preset
            .and_then(|p| p.color.as_deref())
            .unwrap_or(DEFAULT_COLOR),
    );
    let author = preset.and_then(|p| p.author_name.as_deref());

    let is_image = file.content_type.starts_with("image/");
    let is_video = file.content_type.starts_with("video/");

    let size = format_size(
        file.size_bytes.max(0) as u64,
        FormatSizeOptions::from(WINDOWS).decimal_places(1),
    );
    let uploaded = file.created_at.format("%B %-d, %Y at %H:%M UTC");

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta property="og:site_name" content=(site_name);
                meta property="og:title" content=(title);
                meta property="og:description" content=(description);
                meta name="theme-color" content=(color);
                @if is_image {
                    meta property="og:image" content=(raw_url);
                    meta name="twitter:card" content="summary_large_image";
                } @else if is_video {
                    meta property="og:video" content=(raw_url);
                    meta property="og:video:type" content=(file.content_type);
                    meta name="twitter:card" content="player";
                } @else {
                    meta name="twitter:card" content="summary";
                }
                @if let Some(author) = author {
                    meta name="twitter:creator" content=(author);
                }
                style { (PreEscaped(page_css(color))) }
            }
            body {
                @if is_image {
                    img.media src=(raw_url) alt=(title);
                } @else if is_video {
                    video.media src=(raw_url) controls {}
                } @else {
                    a.download-link href=(raw_url) { (title) }
                }
                div.meta { (size) " / uploaded " (uploaded) }
            }
        }
    }
    .into_string()
}

fn page_css(color: &str) -> String {
    format!(
        r#"
:root {{ color-scheme: light dark; }}
body {{
    margin: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    padding: 1rem;
    box-sizing: border-box;
    background: #111;
    color: #eee;
    font-family: system-ui, sans-serif;
}}
.media {{
    max-width: 90vw;
    max-height: 80vh;
    border-radius: 8px;
}}
.download-link {{
    color: {color};
    font-size: 1.5rem;
    text-decoration: none;
}}
.meta {{
    font-size: 0.85rem;
    opacity: 0.7;
}}
"#
    )
}

fn sanitize_color(color: &str) -> &str {
    match color.strip_prefix('#') {
        Some(hex)
            if matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            color
        }
        _ => DEFAULT_COLOR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_file(content_type: &str) -> File {
        File {
            id: "f1".into(),
            user_id: "u1".into(),
            folder_id: None,
            display_name: "abc123.png".into(),
            original_name: "key.png".into(),
            content_type: content_type.into(),
            size_bytes: 70,
            password_hash: None,
            expires_at: None,
            is_favourite: false,
            created_at: Utc::now(),
        }
    }

    fn test_preset(title: &str, color: &str) -> EmbedPreset {
        EmbedPreset {
            id: "p1".into(),
            user_id: "u1".into(),
            name: "default".into(),
            site_name: None,
            site_url: None,
            author_name: None,
            author_url: None,
            title: Some(title.into()),
            description: None,
            color: Some(color.into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn escapes_preset_values() {
        let preset = test_preset(r#""><script>alert(1)</script>"#, "#fff");
        let html = render_embed_html(&test_file("image/png"), "/raw/abc123.png", Some(&preset));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn rejects_non_hex_colors() {
        let preset = test_preset("t", "}</style><script>alert(1)</script>");
        let html = render_embed_html(&test_file("image/png"), "/raw/abc123.png", Some(&preset));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains(DEFAULT_COLOR));
    }

    #[test]
    fn image_files_get_og_image_tags() {
        let html = render_embed_html(&test_file("image/png"), "/raw/abc123.png", None);
        assert!(html.contains(r#"property="og:image" content="/raw/abc123.png""#));
        assert!(html.contains("summary_large_image"));
    }

    #[test]
    fn video_files_get_player_tags() {
        let html = render_embed_html(&test_file("video/mp4"), "/raw/abc123.mp4", None);
        assert!(html.contains(r#"property="og:video""#));
        assert!(html.contains(r#"content="video/mp4""#));
        assert!(html.contains("<video"));
    }
}
