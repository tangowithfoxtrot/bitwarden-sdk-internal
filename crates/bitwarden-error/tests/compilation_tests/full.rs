use bitwarden_error::bitwarden_error;

/// Full errors do not support changing the name of the error in the generated JS
#[bitwarden_error(full, export_as = "SomeOtherError")]
struct SomeError;

fn main() {}
