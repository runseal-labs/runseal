pub(crate) fn unsupported_transport(flag: &str, args: &[String]) -> Result<(), String> {
    match flag {
        "--pipe" | "--socket" => unsupported_same_user_ipc(flag, args),
        "--tcp" | "--http" => Err(format!(
            "service {flag} requires a remote transport RFC and is not implemented"
        )),
        _ => Err(format!("unknown service transport: {flag}")),
    }
}

fn unsupported_same_user_ipc(flag: &str, args: &[String]) -> Result<(), String> {
    if flag == "--socket"
        && args
            .first()
            .is_some_and(|endpoint| endpoint.starts_with('@'))
    {
        return Err(format!(
            "service {flag} requires a filesystem-backed same-user IPC endpoint and is not implemented"
        ));
    }

    Err(format!(
        "service {flag} requires same-user IPC peer authentication and is not implemented"
    ))
}
