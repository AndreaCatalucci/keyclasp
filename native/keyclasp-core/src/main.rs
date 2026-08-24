use keyclasp_core_spike::platform::capabilities;
use std::env;
use std::error::Error;

const STATUS_OPERATION: &str = "status";
const USAGE: &str = "Usage: keyclasp-core-spike status";
const PROTOCOL_VERSION: u8 = 1;

type AppResult<T> = Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("keyclasp-core spike failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    validate_args(&args)?;

    status();
    Ok(())
}

fn validate_args(args: &[String]) -> AppResult<()> {
    if args.len() == 1 && args[0] == STATUS_OPERATION {
        return Ok(());
    }
    Err(USAGE.into())
}

fn status() {
    let capabilities = capabilities();
    println!("protocol_version={PROTOCOL_VERSION}");
    println!("adapter=keyclasp_macos_v1");
    println!("reported_backend={}", capabilities.backend);
    println!(
        "hardware_presence_available={}",
        capabilities.hardware_presence
    );
    println!("touch_id_available={}", capabilities.touch_id_available);
    println!("code_identity={}", capabilities.code_identity);
    println!("required_access_policy=biometric_current_set");
    println!(
        "current_set_policy_available={}",
        capabilities.current_set_policy_available
    );
    println!("lifecycle_operations=disabled");
    println!("enrollment_state=unavailable");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_set_is_status_only() {
        let arguments = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };

        assert!(validate_args(&arguments(&["status"])).is_ok());
        for rejected in [
            arguments(&[]),
            arguments(&["status", "extra"]),
            arguments(&["create"]),
            arguments(&["wrap"]),
            arguments(&["unwrap"]),
            arguments(&["destroy-test-key"]),
            arguments(&["export-key"]),
            arguments(&["shell"]),
        ] {
            assert!(validate_args(&rejected).is_err());
        }
    }
}
