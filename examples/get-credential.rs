use clap::Parser;

/// Invoke `docker_credential::get_credential`.
#[derive(clap::Parser)]
struct GetCredentialOpts {
    /// Server address, for example, `us-docker.pkg.dev`.
    server: String,
}

fn main() -> Result<(), docker_credential::CredentialRetrievalError> {
    let GetCredentialOpts { server } = GetCredentialOpts::parse();

    let credential = docker_credential::get_credential(&server)?;

    eprintln!("{credential:#?}");

    Ok(())
}
