//! Trusted launchd job and IPC authentication primitives for the macOS cohort
//! guardian.
//!
//! The launchd job owns exactly one execution cohort. Its plist and socket live
//! in a per-attempt 0700 directory, are created with 0600, and every launchctl
//! call is time-bounded with capped output. `unregister` verifies that the label
//! is gone; the controller removes the structured ownership record only after
//! kernel zero and runtime-root cleanup. Drop never boots out an unproven job.

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Read};
use std::os::fd::RawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LAUNCHCTL: &str = "/bin/launchctl";
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(5);
const LAUNCHCTL_OUTPUT_LIMIT: u64 = 64 * 1024;

/// A transient per-user launchd job. It never writes to
/// ~/Library/LaunchAgents and never shares its plist or socket directory. The
/// ownership record is created by `prepare`, the plist by `configure`, and the
/// job is registered only by `start`; the controller deletes the structured
/// record after kernel zero and runtime-root cleanup.
pub(crate) struct LaunchdCohortJob {
    label: String,
    private_dir: PathBuf,
    plist_path: PathBuf,
    configured: bool,
    registered: bool,
    label_removed: bool,
}

fn random_hex() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    let result = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut suffix = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut suffix, "{byte:02x}")
            .map_err(|_| io::Error::other("random path suffix formatting failed"))?;
    }
    Ok(suffix)
}

fn random_label() -> io::Result<String> {
    Ok(format!(
        "com.runseal.cohort.{pid}.{suffix}",
        pid = std::process::id(),
        suffix = random_hex()?
    ))
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[derive(Debug)]
struct LaunchctlOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run launchctl with a deadline. `Command::output()` can wait forever if
/// launchd stops answering, so the child is polled, then killed on timeout.
fn run_launchctl(arguments: &[OsString], timeout: Duration) -> io::Result<LaunchctlOutput> {
    let mut child = Command::new(LAUNCHCTL)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "launchctl timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut stream) = child.stdout.take() {
        let _ = Read::take(&mut stream, LAUNCHCTL_OUTPUT_LIMIT).read_to_string(&mut stdout);
    }
    if let Some(mut stream) = child.stderr.take() {
        let _ = Read::take(&mut stream, LAUNCHCTL_OUTPUT_LIMIT).read_to_string(&mut stderr);
    }
    Ok(LaunchctlOutput {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn launchctl_error(action: &str, output: &LaunchctlOutput) -> io::Error {
    let detail = output.stderr.trim();
    io::Error::other(format!(
        "launchctl {action} failed: {}",
        if detail.is_empty() {
            "no stderr"
        } else {
            detail
        }
    ))
}

impl LaunchdCohortJob {
    /// Create the per-attempt 0700 record inside the validated per-user parent.
    /// `create_dir` is exclusive, so an existing path is never reused or shared.
    pub(crate) fn prepare(parent: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let label = random_label()?;
            let private_dir = parent.join(format!("rs-{}", random_hex()?));
            let mut dir_builder = DirBuilder::new();
            dir_builder.mode(0o700);
            match dir_builder.create(&private_dir) {
                Ok(()) => {
                    return Ok(Self {
                        plist_path: private_dir.join("job.plist"),
                        private_dir,
                        label,
                        configured: false,
                        registered: false,
                        label_removed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "could not allocate a unique guardian ownership directory",
        ))
    }

    /// Write the transient plist 0600. The caller runs this after the private
    /// directory, socket, and marker path exist and before `start`.
    pub(crate) fn configure(
        &mut self,
        program: &[String],
        working_directory: &Path,
        environment: &[(&str, &str)],
    ) -> io::Result<()> {
        if self.configured {
            return Err(io::Error::other("launchd job is already configured"));
        }
        if program.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guardian program is empty",
            ));
        }
        let mut plist = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n",
        );
        plist.push_str(&format!(
            "<key>Label</key><string>{}</string>\n",
            xml_escape(&self.label)
        ));
        plist.push_str("<key>ProgramArguments</key><array>\n");
        for argument in program {
            plist.push_str(&format!("<string>{}</string>\n", xml_escape(argument)));
        }
        plist.push_str("</array>\n<key>RunAtLoad</key><true/>\n");
        plist.push_str("<key>KeepAlive</key><false/>\n");
        plist.push_str(&format!(
            "<key>WorkingDirectory</key><string>{}</string>\n",
            xml_escape(&working_directory.to_string_lossy())
        ));
        if !environment.is_empty() {
            plist.push_str("<key>EnvironmentVariables</key><dict>\n");
            for (key, value) in environment {
                plist.push_str(&format!(
                    "<key>{}</key><string>{}</string>\n",
                    xml_escape(key),
                    xml_escape(value)
                ));
            }
            plist.push_str("</dict>\n");
        }
        plist.push_str("</dict></plist>\n");
        let mut plist_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.plist_path)?;
        use std::io::Write as _;
        plist_file.write_all(plist.as_bytes())?;
        plist_file.sync_all()?;
        self.configured = true;
        Ok(())
    }

    /// Register the prepared job. A failed registration never deletes the
    /// ownership record; a confirmed bootout still keeps it for the controller.
    pub(crate) fn start(&mut self) -> io::Result<()> {
        if !self.configured {
            return Err(io::Error::other("launchd job is not configured"));
        }
        if self.registered {
            return Err(io::Error::other("launchd job is already started"));
        }
        let output = match run_launchctl(
            &[
                OsString::from("bootstrap"),
                OsString::from(self.domain()),
                self.plist_path.clone().into_os_string(),
            ],
            LAUNCHCTL_TIMEOUT,
        ) {
            Ok(output) => output,
            Err(error) => {
                return Err(
                    self.start_failure(format!("launchctl bootstrap did not complete: {error}"))
                );
            }
        };
        if !output.success {
            let detail = launchctl_error("bootstrap", &output).to_string();
            return Err(self.start_failure(detail));
        }
        self.registered = true;
        Ok(())
    }

    fn start_failure(&mut self, detail: String) -> io::Error {
        match self.unregister() {
            Ok(()) => io::Error::other(format!(
                "{detail}; the launchd job was booted out after the failed bootstrap"
            )),
            Err(cleanup_error) => io::Error::other(format!(
                "{detail}; cleanup is unconfirmed ({cleanup_error}); ownership record retained at {}",
                self.private_dir.display()
            )),
        }
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn private_dir(&self) -> &Path {
        &self.private_dir
    }

    pub(crate) fn cleanup_record(&self) -> &Path {
        &self.private_dir
    }

    /// launchd domain used by `bootstrap`: gui/<uid>.
    fn domain(&self) -> String {
        format!("gui/{}", unsafe { libc::getuid() })
    }

    /// Main PID reported by launchd for this exact label. The controller uses it
    /// to authenticate the socket peer against the real job identity instead of
    /// any self-reported coalition or process claim.
    pub(crate) fn main_pid(&self) -> io::Result<Option<i32>> {
        label_main_pid(&self.label)
    }

    /// Boot out and verify that the label is no longer registered. The ownership
    /// record stays on disk; the controller deletes it only after runtime-root
    /// cleanup has also succeeded.
    pub(crate) fn unregister(&mut self) -> io::Result<()> {
        if self.label_removed && !self.registered {
            return Ok(());
        }
        unregister_label(&self.label)?;
        self.registered = false;
        self.label_removed = true;
        Ok(())
    }
}

fn service_target_for(label: &str) -> String {
    format!("gui/{}/{}", unsafe { libc::getuid() }, label)
}

/// Whether launchd currently has this exact label registered.
pub(crate) fn label_registered(label: &str) -> io::Result<bool> {
    let print = run_launchctl(
        &[
            OsString::from("print"),
            OsString::from(service_target_for(label)),
        ],
        LAUNCHCTL_TIMEOUT,
    )?;
    Ok(print.success)
}

/// Main PID of a label, if launchd reports it as running.
pub(crate) fn label_main_pid(label: &str) -> io::Result<Option<i32>> {
    let print = run_launchctl(
        &[
            OsString::from("print"),
            OsString::from(service_target_for(label)),
        ],
        LAUNCHCTL_TIMEOUT,
    )?;
    if !print.success {
        return Ok(None);
    }
    Ok(parse_launchd_pid(&print.stdout))
}

/// Boot out a label and positively verify it is no longer registered. Used by
/// both normal finalization and startup recovery; the ownership record is never
/// deleted here.
pub(crate) fn unregister_label(label: &str) -> io::Result<()> {
    let target = service_target_for(label);
    let _bootout = run_launchctl(
        &[OsString::from("bootout"), OsString::from(target.as_str())],
        LAUNCHCTL_TIMEOUT,
    )?;
    // The verified absence of the label is authoritative; a failed bootout for a
    // never-registered job is covered by that check.
    let print = run_launchctl(
        &[OsString::from("print"), OsString::from(target.as_str())],
        LAUNCHCTL_TIMEOUT,
    )?;
    if print.success {
        return Err(io::Error::other(
            "launchd job is still registered after bootout",
        ));
    }
    let text = format!("{}\n{}", print.stdout, print.stderr);
    if !text.contains("Could not find")
        && !text.contains("not find service")
        && !text.contains("No such process")
    {
        return Err(io::Error::other(format!(
            "launchd job removal could not be confirmed: {}",
            text.trim()
        )));
    }
    Ok(())
}

fn parse_launchd_pid(stdout: &str) -> Option<i32> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|value| value.trim().parse::<i32>().ok())
    })
}

impl Drop for LaunchdCohortJob {
    fn drop(&mut self) {
        // Intentionally empty. A job whose kernel zero has not been proven must
        // stay registered so the coalition counters and ownership record remain
        // available to the explicit finalizer/recovery path. Drop never boots
        // out and never deletes the ownership record.
    }
}

pub(crate) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
