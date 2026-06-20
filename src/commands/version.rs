use super::*;

pub(crate) fn payload() -> Value {
    json!({
        "runseal_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "policy_versions": [POLICY_VERSION],
    })
}

pub(crate) fn print_plain() -> Result<(), String> {
    println!("{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

pub(crate) fn print_json() -> Result<(), String> {
    println!("{}", payload());
    Ok(())
}
