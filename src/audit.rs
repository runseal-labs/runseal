use crate::error::RunSealError;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct AuditWriter {
    file: File,
    relative_path: String,
}

impl AuditWriter {
    pub fn create(cwd: &Path, session_id: &str) -> io::Result<Self> {
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
        object.insert("metadata".to_string(), metadata.clone());
    }
    write_audit_event(audit, &audit_event)
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
}
