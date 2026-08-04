use crate::error::AppError;

pub struct EmbedVariable {
    pub name: &'static str,
    pub description: &'static str,
}

pub const EMBED_VARIABLES: &[EmbedVariable] = &[
    EmbedVariable {
        name: "filename",
        description: "the file's display name, e.g. abc123.png",
    },
    EmbedVariable {
        name: "size",
        description: "human readable file size, e.g. 1.4 MB",
    },
    EmbedVariable {
        name: "uploader",
        description: "username of the account that uploaded the file",
    },
    EmbedVariable {
        name: "date",
        description: "upload date, e.g. July 9, 2026 at 17:26 UTC",
    },
    EmbedVariable {
        name: "type",
        description: "the file's content type, e.g. image/png",
    },
];

#[derive(Debug, Clone)]
pub struct EmbedVars {
    pub filename: String,
    pub size: String,
    pub uploader: String,
    pub date: String,
    pub content_type: String,
}

impl EmbedVars {
    fn lookup(&self, name: &str) -> Option<&str> {
        Some(match name {
            n if n.eq_ignore_ascii_case("filename") => &self.filename,
            n if n.eq_ignore_ascii_case("size") => &self.size,
            n if n.eq_ignore_ascii_case("uploader") => &self.uploader,
            n if n.eq_ignore_ascii_case("date") => &self.date,
            n if n.eq_ignore_ascii_case("type") => &self.content_type,
            _ => return None,
        })
    }
}

fn is_known(name: &str) -> bool {
    EMBED_VARIABLES
        .iter()
        .any(|v| v.name.eq_ignore_ascii_case(name))
}

enum Chunk<'a> {
    Text(&'a str),
    Var(&'a str),
}

fn chunks(template: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    let mut rest = template;

    while let Some(open) = rest.find(['{', '}']) {
        let (text, tail) = rest.split_at(open);
        if !text.is_empty() {
            out.push(Chunk::Text(text));
        }

        let brace = &tail[..1];
        if tail[1..].starts_with(brace) {
            out.push(Chunk::Text(brace));
            rest = &tail[2..];
            continue;
        }

        match tail.find('}').filter(|_| brace == "{") {
            Some(close) => {
                out.push(Chunk::Var(&tail[1..close]));
                rest = &tail[close + 1..];
            }
            None => {
                out.push(Chunk::Text(brace));
                rest = &tail[1..];
            }
        }
    }

    if !rest.is_empty() {
        out.push(Chunk::Text(rest));
    }
    out
}

pub fn render(template: &str, vars: &EmbedVars) -> String {
    let mut out = String::with_capacity(template.len());
    for chunk in chunks(template) {
        match chunk {
            Chunk::Text(text) => out.push_str(text),
            Chunk::Var(name) => match vars.lookup(name) {
                Some(value) => out.push_str(value),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            },
        }
    }
    out
}

pub fn validate(template: &str, label: &str) -> Result<(), AppError> {
    let unknown: Vec<&str> = chunks(template)
        .into_iter()
        .filter_map(|c| match c {
            Chunk::Var(name) if !is_known(name) => Some(name),
            _ => None,
        })
        .collect();

    if unknown.is_empty() {
        return Ok(());
    }

    let known = EMBED_VARIABLES
        .iter()
        .map(|v| format!("{{{}}}", v.name))
        .collect::<Vec<_>>()
        .join(", ");

    Err(AppError::BadRequest(format!(
        "{label} uses unknown variable{} {} supported: {known} (use {{{{ for a literal brace)",
        if unknown.len() == 1 { "" } else { "s" },
        unknown
            .iter()
            .map(|n| format!("{{{n}}}"))
            .collect::<Vec<_>>()
            .join(", "),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> EmbedVars {
        EmbedVars {
            filename: "abc123.png".into(),
            size: "1.4 MB".into(),
            uploader: "cat".into(),
            date: "July 9, 2026 at 17:26 UTC".into(),
            content_type: "image/png".into(),
        }
    }

    #[test]
    fn substitutes_every_variable() {
        let out = render("{filename} {size} {uploader} {date} {type}", &vars());
        assert_eq!(
            out,
            "abc123.png 1.4 MB cat July 9, 2026 at 17:26 UTC image/png"
        );
    }

    #[test]
    fn variable_names_are_case_insensitive() {
        assert_eq!(render("{FileName}", &vars()), "abc123.png");
    }

    #[test]
    fn keeps_surrounding_text() {
        assert_eq!(
            render("uploaded by {uploader} ({size})", &vars()),
            "uploaded by cat (1.4 MB)"
        );
    }

    #[test]
    fn doubled_braces_are_literal() {
        assert_eq!(render("{{filename}}", &vars()), "{filename}");
        assert_eq!(render("a {{ b }} c", &vars()), "a { b } c");
        assert!(validate("{{nope}}", "title").is_ok());
    }

    #[test]
    fn unmatched_braces_are_left_alone() {
        assert_eq!(render("100% {sure", &vars()), "100% {sure");
        assert_eq!(render("closing } brace", &vars()), "closing } brace");
        assert!(validate("100% {sure", "title").is_ok());
    }

    #[test]
    fn unknown_variables_survive_rendering() {
        assert_eq!(render("{nope} {size}", &vars()), "{nope} 1.4 MB");
    }

    #[test]
    fn validate_rejects_unknown_variables() {
        let err = validate("{filename} {nope} {alsonope}", "title").unwrap_err();
        let AppError::BadRequest(message) = err else {
            panic!("expected BadRequest");
        };
        assert!(message.contains("{nope}"), "{message}");
        assert!(message.contains("{alsonope}"), "{message}");
        assert!(message.contains("title"), "{message}");
    }

    #[test]
    fn validate_accepts_known_variables() {
        assert!(validate("{filename} on {date}", "description").is_ok());
        assert!(validate("no variables at all", "description").is_ok());
    }

    #[test]
    fn empty_placeholder_is_unknown() {
        assert_eq!(render("{}", &vars()), "{}");
        assert!(validate("{}", "title").is_err());
    }
}
