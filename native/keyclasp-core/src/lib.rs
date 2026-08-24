// The lifecycle slice is compiled and tested but intentionally has no runtime
// entrypoint until recovery and physical-device qualification are complete.
#[allow(dead_code)]
#[cfg(target_os = "macos")]
mod macos_backend;
#[allow(dead_code)]
#[cfg(target_os = "macos")]
mod owner_file;
#[allow(dead_code)]
pub mod platform;
#[allow(dead_code)]
#[cfg(target_os = "macos")]
mod recovery;
#[allow(dead_code)]
#[cfg(target_os = "macos")]
mod transaction;
#[allow(dead_code)]
#[cfg(target_os = "macos")]
mod vault_key;

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("lib.rs");

    #[test]
    fn lifecycle_modules_are_not_public_runtime_entrypoints() {
        let public_modules = SOURCE
            .lines()
            .filter_map(|line| line.split("//").next())
            .map(str::trim)
            .filter(|line| line.starts_with("pub mod "))
            .collect::<Vec<_>>();
        assert_eq!(public_modules, vec!["pub mod platform;"]);
        assert!(!SOURCE
            .lines()
            .filter_map(|line| line.split("//").next())
            .any(|line| line.trim().starts_with("pub use ")));
    }
}
