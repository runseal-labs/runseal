use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use tracing_appender::rolling::RollingFileAppender;
use tracing_appender::rolling::Rotation;

pub const LOG_FILE_PREFIX: &str = "sandbox";
pub const LOG_FILE_SUFFIX: &str = "log";
pub const MAX_LOG_FILES: usize = 90;

fn exe_label() -> &'static str {
    static LABEL: OnceLock<String> = OnceLock::new();
    LABEL.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "proc".to_string())
    })
}

pub fn log_file_path_for_utc_date(base_dir: &Path, date: chrono::NaiveDate) -> PathBuf {
    base_dir.join(format!(
        "{LOG_FILE_PREFIX}.{}.{}",
        date.format("%Y-%m-%d"),
        LOG_FILE_SUFFIX
    ))
}

pub fn current_log_file_path(base_dir: &Path) -> PathBuf {
    log_file_path_for_utc_date(base_dir, chrono::Utc::now().date_naive())
}

pub fn current_log_file_path_for_codex_home(codex_home: &Path) -> PathBuf {
    current_log_file_path(&crate::sandbox_dir(codex_home))
}

pub fn log_writer(base_dir: &Path) -> Option<RollingFileAppender> {
    if !base_dir.is_dir() {
        return None;
    }

    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(MAX_LOG_FILES)
        .build(base_dir)
        .ok()
}

fn append_line(line: &str, base_dir: Option<&Path>) {
    if let Some(dir) = base_dir
        && let Some(mut f) = log_writer(dir)
    {
        let _ = writeln!(f, "{line}");
    }
}

pub fn log_start(_command: &[String], base_dir: Option<&Path>) {
    log_note("START", base_dir);
}

pub fn log_success(_command: &[String], base_dir: Option<&Path>) {
    log_note("SUCCESS", base_dir);
}

pub fn log_failure(_command: &[String], _detail: &str, base_dir: Option<&Path>) {
    log_note("FAILURE", base_dir);
}

// Debug logging helper. Emits only when SBX_DEBUG=1 to avoid noisy logs.
pub fn debug_log(msg: &str, base_dir: Option<&Path>) {
    if std::env::var("SBX_DEBUG").ok().as_deref() == Some("1") {
        append_line(&format!("DEBUG: {msg}"), base_dir);
        eprintln!("{msg}");
    }
}

// Unconditional note logging to the daily sandbox log.
pub fn log_note(msg: &str, base_dir: Option<&Path>) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    append_line(&format!("[{ts} {}] {}", exe_label(), msg), base_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_notes_do_not_retain_argv_or_raw_error_bodies() {
        let temp = tempfile::tempdir().unwrap();
        let command = vec![
            "program-secret-canary".to_string(),
            "argument-secret-canary".to_string(),
        ];
        log_start(&command, Some(temp.path()));
        log_success(&command, Some(temp.path()));
        log_failure(&command, "diagnostic-secret-canary", Some(temp.path()));
        let contents = std::fs::read_to_string(current_log_file_path(temp.path())).unwrap();
        for secret in [
            "program-secret-canary",
            "argument-secret-canary",
            "diagnostic-secret-canary",
        ] {
            assert!(!contents.contains(secret));
        }
        for phase in ["START", "SUCCESS", "FAILURE"] {
            assert!(contents.contains(phase));
        }
    }

    #[test]
    fn log_note_writes_to_daily_rolling_log() {
        let tempdir = tempfile::tempdir().expect("tempdir");

        log_note("hello daily log", Some(tempdir.path()));

        let entries = std::fs::read_dir(tempdir.path())
            .expect("read log dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("read entries");
        assert_eq!(entries.len(), 1);

        let log_path = entries[0].path();
        let filename = log_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 filename");
        assert!(filename.starts_with("sandbox."));
        assert!(filename.ends_with(".log"));

        let log = std::fs::read_to_string(log_path).expect("read log");
        assert!(log.contains("hello daily log"));
    }

    #[test]
    fn log_file_path_for_utc_date_matches_rolling_appender_name() {
        let date = chrono::NaiveDate::from_ymd_opt(2026, 5, 21).expect("valid date");

        assert_eq!(
            log_file_path_for_utc_date(Path::new("logs"), date),
            PathBuf::from("logs").join("sandbox.2026-05-21.log")
        );
    }

    #[test]
    fn current_log_file_path_for_codex_home_uses_sandbox_dir() {
        let codex_home = Path::new("codex-home");

        assert_eq!(
            current_log_file_path_for_codex_home(codex_home),
            current_log_file_path(&codex_home.join(".sandbox"))
        );
    }
}
