#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, TryRngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsString,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use tauri::{Manager, State};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreBootstrap {
    api_base_url: String,
    credential: String,
}

struct CoreState {
    bootstrap: CoreBootstrap,
    port: u16,
    child: Mutex<Option<Child>>,
}

impl CoreState {
    fn stop(&self) {
        if let Ok(mut owned) = self.child.lock() {
            if let Some(mut child) = owned.take() {
                let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
                let _ = authenticated_request(
                    address,
                    "POST",
                    "/api/v1/shutdown",
                    &self.bootstrap.credential,
                    "\"status\":\"shutting_down\"",
                );
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        let _ = child.wait();
                        return;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[tauri::command]
fn core_bootstrap(state: State<'_, CoreState>) -> CoreBootstrap {
    state.bootstrap.clone()
}

fn launch_credential() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "secure credential generation failed".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn reserve_loopback_port() -> Result<u16, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "no loopback port is available".to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| "loopback port selection failed".to_string())
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
        .to_path_buf()
}

fn development_python(root: &Path) -> PathBuf {
    let candidates = if cfg!(windows) {
        vec![
            root.join(".venv").join("Scripts").join("python.exe"),
            PathBuf::from("python"),
        ]
    } else {
        vec![
            root.join(".venv").join("bin").join("python"),
            PathBuf::from("python3"),
        ]
    };
    candidates
        .into_iter()
        .find(|candidate| !candidate.is_absolute() || candidate.is_file())
        .unwrap_or_else(|| PathBuf::from("python3"))
}

fn packaged_core_path() -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        if let Some(configured) = env::var_os("PENTAI_CORE_EXECUTABLE") {
            return Ok(PathBuf::from(configured));
        }
        return Ok(development_python(&repository_root()));
    }
    let executable =
        env::current_exe().map_err(|_| "desktop executable location is unavailable".to_string())?;
    let filename = if cfg!(windows) {
        "pentai-core.exe"
    } else {
        "pentai-core"
    };
    executable
        .parent()
        .map(|directory| directory.join(filename))
        .filter(|candidate| candidate.is_file())
        .ok_or_else(|| "packaged core executable is missing".to_string())
        .and_then(verify_packaged_core)
}

fn verify_packaged_core(candidate: PathBuf) -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        return Ok(candidate);
    }
    let actual = file_sha256(&candidate)?;
    if actual != env!("PENTAI_CORE_SIDECAR_SHA256") {
        return Err("packaged core integrity verification failed".to_string());
    }
    Ok(candidate)
}

fn file_sha256(candidate: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(candidate).map_err(|_| "packaged core could not be read".to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn python_path(root: &Path) -> Result<OsString, String> {
    env::join_paths([
        root.join("services").join("core").join("src"),
        root.join("packages").join("policy").join("src"),
    ])
    .map_err(|_| "development Python path is invalid".to_string())
}

fn spawn_core(credential: &str, port: u16, database_path: &Path) -> Result<Child, String> {
    let executable = packaged_core_path()?;
    let mut command = Command::new(&executable);
    if cfg!(debug_assertions) && env::var_os("PENTAI_CORE_EXECUTABLE").is_none() {
        let root = repository_root();
        command
            .args(["-m", "pentai_core.server"])
            .current_dir(&root)
            .env("PYTHONPATH", python_path(&root)?)
            .env("PENTAI_ENVIRONMENT", "development");
    } else {
        command.env("PENTAI_ENVIRONMENT", "production");
    }
    command
        .env_remove("PENTAI_TEST_MODE")
        .env("PENTAI_CORE_HOST", "127.0.0.1")
        .env("PENTAI_CORE_PORT", port.to_string())
        .env("PENTAI_DATABASE_PATH", database_path)
        .env("PENTAI_LAUNCH_CREDENTIAL", credential)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "core process could not be started".to_string())
}

fn authenticated_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    credential: &str,
    expected_body: &str,
) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(200)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {credential}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok()
        && response.starts_with("HTTP/1.1 200")
        && response.contains(expected_body)
}

fn readiness_request(address: SocketAddr, credential: &str) -> bool {
    authenticated_request(
        address,
        "GET",
        "/api/v1/readiness",
        credential,
        "\"status\":\"ready\"",
    )
}

fn wait_until_ready(child: &mut Child, port: u16, credential: &str) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| "core process status is unavailable".to_string())?
            .is_some()
        {
            return Err("core process exited before readiness".to_string());
        }
        if readiness_request(address, credential) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("core readiness timed out".to_string())
}

fn main() {
    let application = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![core_bootstrap])
        .setup(|app| {
            let credential = launch_credential()?;
            let port = reserve_loopback_port()?;
            let data_directory = app
                .path()
                .app_data_dir()
                .map_err(|_| "application data directory is unavailable".to_string())?;
            std::fs::create_dir_all(&data_directory)
                .map_err(|_| "application data directory could not be created".to_string())?;
            let mut child = spawn_core(&credential, port, &data_directory.join("pentai.db"))?;
            if let Err(error) = wait_until_ready(&mut child, port, &credential) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
            app.manage(CoreState {
                bootstrap: CoreBootstrap {
                    api_base_url: format!("http://127.0.0.1:{port}/api/v1"),
                    credential,
                },
                port,
                child: Mutex::new(Some(child)),
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to initialize PentAI desktop");

    application.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            if let Some(state) = app_handle.try_state::<CoreState>() {
                state.stop();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_credentials_are_256_bit_url_safe_values() {
        let credential = launch_credential().expect("credential");
        assert_eq!(credential.len(), 43);
        assert!(credential
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')));
    }

    #[test]
    fn selected_ports_are_loopback_bindable() {
        let port = reserve_loopback_port().expect("port");
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[test]
    fn compiled_sidecar_identity_matches_the_built_binary() {
        let sidecar =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(env!("PENTAI_CORE_SIDECAR_BUILD_PATH"));
        assert_eq!(
            file_sha256(&sidecar).expect("sidecar digest"),
            env!("PENTAI_CORE_SIDECAR_SHA256")
        );
    }
}
