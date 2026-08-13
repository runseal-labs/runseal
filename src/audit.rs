use crate::error::RunSealError;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAX_AUDIT_SESSION_ID_BYTES: usize = 128;
const REDACTED: &str = "[REDACTED]";

pub struct AuditWriter {
    file: File,
    relative_path: String,
}

impl AuditWriter {
    pub fn create(cwd: &Path, session_id: &str) -> io::Result<Self> {
        validate_audit_session_id(session_id)?;
        let audit_dir = cwd.join(".runseal").join("audit");
        fs::create_dir_all(&audit_dir)?;

        let file_name = format!("{session_id}.jsonl");
        let path = audit_dir.join(file_name);
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;

        Ok(Self {
            file,
            relative_path: audit_path(session_id),
        })
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn write_event(&mut self, event: &Value) -> io::Result<()> {
        serde_json::to_writer(&mut self.file, event).map_err(io::Error::other)?;
        self.file.write_all(b"\n")?;
        self.file.flush()
    }
}

fn validate_audit_session_id(session_id: &str) -> io::Result<()> {
    if session_id.starts_with("sess_")
        && session_id.len() > "sess_".len()
        && session_id.len() <= MAX_AUDIT_SESSION_ID_BYTES
        && session_id
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid audit session id",
    ))
}

fn audit_path(session_id: &str) -> String {
    PathBuf::from(".runseal")
        .join("audit")
        .join(format!("{session_id}.jsonl"))
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn create_audit_writer(
    cwd: &Path,
    session_id: &str,
) -> Result<AuditWriter, RunSealError> {
    AuditWriter::create(cwd, session_id).map_err(|err| {
        RunSealError::new(
            "INTERNAL_ERROR",
            format!("failed to create audit writer: {err}"),
        )
    })
}

fn write_audit_event(audit: &mut AuditWriter, event: &Value) -> Result<(), RunSealError> {
    audit.write_event(event).map_err(|err| {
        RunSealError::new(
            "INTERNAL_ERROR",
            format!("failed to write audit event: {err}"),
        )
    })
}

pub(crate) fn write_audit_event_with_metadata(
    audit: &mut AuditWriter,
    event: &Value,
    metadata: &Option<Value>,
) -> Result<(), RunSealError> {
    let Some(metadata) = metadata else {
        return write_audit_event(audit, event);
    };

    let mut audit_event = event.clone();
    if let Some(object) = audit_event.as_object_mut() {
        object.insert("metadata".to_string(), redact_audit_value(metadata));
    }
    write_audit_event(audit, &audit_event)
}

fn redact_audit_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_audit_key(key) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_audit_value(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_audit_value).collect()),
        Value::String(value) => Value::String(redact_url_value(value)),
        _ => value.clone(),
    }
}

/// Redact credential-bearing material from a URL-like string value.
///
/// Fail-closed rules:
/// - URL values with userinfo (`user:pass@`), a query, or a fragment are
///   projected to `scheme://[REDACTED]@host[:port]` (or `scheme://host[:port]`
///   when there is no userinfo), dropping path, query, and fragment, which are
///   common credential carriers such as signed-URL and OAuth tokens.
/// - URL-like values (containing `://`) that cannot be parsed are replaced
///   entirely with `[REDACTED]`.
/// - Benign URLs and non-URL strings pass through unchanged.
fn redact_url_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return value.to_string();
    }

    let Ok(url) = url::Url::parse(trimmed) else {
        if trimmed.contains("://") {
            return REDACTED.to_string();
        }
        return value.to_string();
    };

    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    let has_query = url.query().is_some();
    let has_fragment = url.fragment().is_some();
    if !has_userinfo && !has_query && !has_fragment {
        return value.to_string();
    }

    let host = match url.host() {
        Some(url::Host::Domain(domain)) => domain.to_string(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        None => "<none>".to_string(),
    };
    let port = url
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));

    let mut redacted = format!("{}://", url.scheme());
    if has_userinfo {
        redacted.push_str(REDACTED);
        redacted.push('@');
    }
    redacted.push_str(&host);
    redacted.push_str(&port);
    redacted
}

fn is_sensitive_audit_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "api_key"
            | "access_token"
            | "refresh_token"
            | "token"
            | "password"
            | "secret"
    ) || key.ends_with("_token")
        || key.ends_with("_key")
        || key.ends_with("_secret")
        || key.ends_with("_password")
        || key.ends_with("_authorization")
        || key.ends_with("_cookie")
        || key.starts_with("aws_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn audit_writer_does_not_overwrite_existing_session_file() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let mut writer = AuditWriter::create(tmp.path(), "sess_collision")?;
        writer.write_event(&json!({"type": "first"}))?;
        drop(writer);

        let Err(err) = AuditWriter::create(tmp.path(), "sess_collision") else {
            panic!("existing audit file must not be overwritten");
        };

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let audit_file = tmp
            .path()
            .join(".runseal")
            .join("audit")
            .join("sess_collision.jsonl");
        assert!(fs::read_to_string(audit_file)?.contains("\"first\""));
        Ok(())
    }

    #[test]
    fn audit_writer_rejects_path_like_session_ids() -> io::Result<()> {
        let tmp = TempDir::new()?;

        for session_id in ["../sess_escape", "sess_../escape", "sess_escape/path"] {
            let Err(err) = AuditWriter::create(tmp.path(), session_id) else {
                panic!("path-like session id must be rejected: {session_id}");
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        Ok(())
    }

    #[test]
    fn audit_writer_rejects_empty_session_id_suffix() -> io::Result<()> {
        let tmp = TempDir::new()?;

        let Err(err) = AuditWriter::create(tmp.path(), "sess_") else {
            panic!("empty session id suffix must be rejected");
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn audit_writer_rejects_overlong_session_ids() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let session_id = format!("sess_{}", "a".repeat(MAX_AUDIT_SESSION_ID_BYTES));

        let Err(err) = AuditWriter::create(tmp.path(), &session_id) else {
            panic!("overlong session id must be rejected");
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn audit_metadata_redacts_sensitive_keys_recursively() {
        let metadata = json!({
            "Authorization": "Bearer secret",
            "nested": {
                "Cookie": "session=secret",
                "safe": "visible"
            },
            "items": [
                {"proxy-authorization": "Basic secret"},
                {"token": "secret"},
                {"github_token": "secret"},
                {"service_api_key": "secret"},
                {"aws_region": "secret"},
                {"proxy_url": "http://user:secret@example.invalid:8080/path"}
            ]
        });

        assert_eq!(
            redact_audit_value(&metadata),
            json!({
                "Authorization": REDACTED,
                "nested": {
                    "Cookie": REDACTED,
                    "safe": "visible"
                },
                "items": [
                    {"proxy-authorization": REDACTED},
                    {"token": REDACTED},
                    {"github_token": REDACTED},
                    {"service_api_key": REDACTED},
                    {"aws_region": REDACTED},
                    {"proxy_url": "http://[REDACTED]@example.invalid:8080"}
                ]
            })
        );
    }

    #[test]
    fn redact_url_value_projects_credential_carriers_to_authority() {
        let cases = [
            (
                "http://user:secret@example.invalid:8080/path",
                "http://[REDACTED]@example.invalid:8080",
            ),
            (
                "https://user@example.invalid/private",
                "https://[REDACTED]@example.invalid",
            ),
            (
                "socks5://:secret@proxy.example.test:1080",
                "socks5://[REDACTED]@proxy.example.test:1080",
            ),
            (
                "http://PERCENT%2DENCODED%2DUSER:PERCENT%2DENCODED%2DPASS@proxy.example.test:8080",
                "http://[REDACTED]@proxy.example.test:8080",
            ),
            (
                "http://user:secret@[2001:db8::1]:3128/IPV6CANARY",
                "http://[REDACTED]@[2001:db8::1]:3128",
            ),
            (
                "https://index.example.test/simple?token=QUERYCANARY",
                "https://index.example.test",
            ),
            (
                "https://index.example.test:8443/simple?X-Amz-Credential=SIGNCANARY&X-Amz-Signature=SIGCANARY",
                "https://index.example.test:8443",
            ),
            (
                "https://example.test/callback#access_token=FRAGCANARY",
                "https://example.test",
            ),
            (
                "https://user:secret@example.test/path?token=QUERYCANARY#frag=FRAGCANARY",
                "https://[REDACTED]@example.test",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(redact_url_value(input), expected, "input={input}");
        }
    }

    #[test]
    fn redact_url_value_keeps_benign_values_unchanged() {
        let benign = [
            "https://example.invalid/docs",
            "http://127.0.0.1:43128",
            "https://index.example.test/simple",
            "file:///private/tmp/simple",
            "runseal://local",
            "plain text without urls",
            "  https://example.invalid  ",
            "",
            "no-scheme-value",
        ];

        for input in benign {
            assert_eq!(redact_url_value(input), input, "input={input}");
        }
    }

    #[test]
    fn redact_url_value_fails_closed_on_ambiguous_values() {
        let ambiguous = [
            "http://user:pass?token=x@example.invalid",
            "not a url://with spaces",
            "http://host:notaport/path",
            "http://[broken ipv6/path",
            "://missing-scheme",
        ];

        for input in ambiguous {
            assert_eq!(redact_url_value(input), REDACTED, "input={input}");
        }
    }
}
