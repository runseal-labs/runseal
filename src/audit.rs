use serde_json::Value;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct AuditWriter {
    file: File,
    relative_path: String,
}

impl AuditWriter {
    pub fn create(cwd: &Path, execution_id: &str) -> io::Result<Self> {
        let audit_dir = cwd.join(".runseal").join("audit");
        fs::create_dir_all(&audit_dir)?;

        let file_name = format!("{execution_id}.jsonl");
        let path = audit_dir.join(file_name);
        let file = File::create(path)?;

        Ok(Self {
            file,
            relative_path: audit_path(execution_id),
        })
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn write_event(&mut self, event: &Value) -> io::Result<()> {
        serde_json::to_writer(&mut self.file, event)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        self.file.write_all(b"\n")?;
        self.file.flush()
    }
}

fn audit_path(execution_id: &str) -> String {
    PathBuf::from(".runseal")
        .join("audit")
        .join(format!("{execution_id}.jsonl"))
        .to_string_lossy()
        .replace('\\', "/")
}
