#[cfg(target_os = "macos")]
#[path = "credentials/broker_peer_auth.rs"]
mod broker_peer_auth;
#[path = "credentials/broker_protocol.rs"]
mod broker_protocol;
#[path = "credentials/broker_server.rs"]
mod broker_server;

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        eprintln!("usage: unpin-credential-broker --app-state-root PATH");
        return std::process::ExitCode::from(2);
    };
    if command == "--version" && arguments.next().is_none() {
        println!(
            "unpin-credential-broker {} protocol 1",
            env!("CARGO_PKG_VERSION")
        );
        return std::process::ExitCode::SUCCESS;
    }
    if (command == "--help" || command == "-h") && arguments.next().is_none() {
        println!("usage: unpin-credential-broker --app-state-root PATH");
        return std::process::ExitCode::SUCCESS;
    }
    if command != "--app-state-root" {
        eprintln!("usage: unpin-credential-broker --app-state-root PATH");
        return std::process::ExitCode::from(2);
    }
    let Some(app_state_root) = arguments.next() else {
        eprintln!("credential broker app state root is missing");
        return std::process::ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("credential broker received unexpected arguments");
        return std::process::ExitCode::from(2);
    }
    match broker_server::run(std::path::Path::new(&app_state_root)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential broker failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
