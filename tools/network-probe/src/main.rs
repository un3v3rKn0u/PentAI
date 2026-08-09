use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::process;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

struct Arguments {
    network_id: String,
    direct_ip: IpAddr,
    dns_ip: IpAddr,
    ipv6: IpAddr,
}

fn main() {
    let arguments = match parse_arguments(env::args().skip(1)) {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("pentai-network-probe: {message}");
            process::exit(2);
        }
    };

    let direct_egress_blocked = connection_blocked(arguments.direct_ip, 9);
    let external_dns_blocked = connection_blocked(arguments.dns_ip, 53);
    let ipv6_blocked = connection_blocked(arguments.ipv6, 9);
    let runtime_socket_blocked = runtime_socket_blocked();
    let host_mounts_blocked = host_mounts_blocked();
    let host_namespaces_blocked = process::id() == 1;
    let resource_limits_enforced = resource_limits_enforced();

    println!(
        concat!(
            "{{\"network_id\":\"{}\",",
            "\"direct_egress_blocked\":{},",
            "\"external_dns_blocked\":{},",
            "\"ipv6_blocked\":{},",
            "\"runtime_socket_blocked\":{},",
            "\"host_mounts_blocked\":{},",
            "\"host_namespaces_blocked\":{},",
            "\"resource_limits_enforced\":{}}}"
        ),
        arguments.network_id,
        direct_egress_blocked,
        external_dns_blocked,
        ipv6_blocked,
        runtime_socket_blocked,
        host_mounts_blocked,
        host_namespaces_blocked,
        resource_limits_enforced,
    );
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, &'static str> {
    let mut format_seen = false;
    let mut network_id = None;
    let mut direct_ip = None;
    let mut dns_ip = None;
    let mut ipv6 = None;

    for argument in arguments {
        if argument == "--format=json" && !format_seen {
            format_seen = true;
        } else if let Some(value) = argument.strip_prefix("--network-id=") {
            if network_id.is_some() || !valid_identifier(value) {
                return Err("invalid network identity");
            }
            network_id = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix("--direct-ip=") {
            direct_ip = parse_exact_ip(direct_ip, value, "192.0.2.1")?;
        } else if let Some(value) = argument.strip_prefix("--dns-ip=") {
            dns_ip = parse_exact_ip(dns_ip, value, "192.0.2.53")?;
        } else if let Some(value) = argument.strip_prefix("--ipv6=") {
            ipv6 = parse_exact_ip(ipv6, value, "2001:db8::1")?;
        } else {
            return Err("unsupported or duplicate argument");
        }
    }

    match (format_seen, network_id, direct_ip, dns_ip, ipv6) {
        (true, Some(network_id), Some(direct_ip), Some(dns_ip), Some(ipv6)) => Ok(Arguments {
            network_id,
            direct_ip,
            dns_ip,
            ipv6,
        }),
        _ => Err("required argument is missing"),
    }
}

fn valid_identifier(value: &str) -> bool {
    let length = value.len();
    (1..=128).contains(&length)
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn parse_exact_ip(
    current: Option<IpAddr>,
    value: &str,
    expected: &str,
) -> Result<Option<IpAddr>, &'static str> {
    if current.is_some() || value != expected {
        return Err("probe destination is not an approved TEST-NET address");
    }
    value
        .parse::<IpAddr>()
        .map(Some)
        .map_err(|_| "probe destination is invalid")
}

fn connection_blocked(ip: IpAddr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT).is_err()
}

fn runtime_socket_blocked() -> bool {
    env::var_os("DOCKER_HOST").is_none()
        && env::var_os("CONTAINER_HOST").is_none()
        && [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/podman/podman.sock",
        ]
        .iter()
        .all(|path| !Path::new(path).exists())
}

fn host_mounts_blocked() -> bool {
    let forbidden_paths = ["/host", "/hostfs", "/workspace-host", "/var/lib/docker"];
    if forbidden_paths.iter().any(|path| Path::new(path).exists()) {
        return false;
    }
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    !mountinfo.lines().any(|line| {
        let mount_point = line.split_whitespace().nth(4).unwrap_or("");
        forbidden_paths.contains(&mount_point)
    })
}

fn resource_limits_enforced() -> bool {
    let memory = read_trimmed("/sys/fs/cgroup/memory.max")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value <= 32 * 1024 * 1024);
    let pids = read_trimmed("/sys/fs/cgroup/pids.max")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value <= 16);
    let cpu = read_trimmed("/sys/fs/cgroup/cpu.max").is_some_and(|value| {
        let mut parts = value.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some(quota), Some(period), None) if quota != "max" => {
                match (quota.parse::<u64>(), period.parse::<u64>()) {
                    (Ok(quota), Ok(period)) => quota.saturating_mul(4) <= period,
                    _ => false,
                }
            }
            _ => false,
        }
    });
    memory && pids && cpu
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved_arguments() -> impl Iterator<Item = String> {
        [
            "--format=json",
            "--network-id=network-1",
            "--direct-ip=192.0.2.1",
            "--dns-ip=192.0.2.53",
            "--ipv6=2001:db8::1",
        ]
        .into_iter()
        .map(str::to_owned)
    }

    #[test]
    fn accepts_only_complete_approved_arguments() {
        let parsed = parse_arguments(approved_arguments()).expect("approved arguments");
        assert_eq!(parsed.network_id, "network-1");
        assert_eq!(parsed.direct_ip.to_string(), "192.0.2.1");
    }

    #[test]
    fn rejects_real_or_changed_destinations() {
        for argument in ["--direct-ip=8.8.8.8", "--dns-ip=127.0.0.1", "--ipv6=::1"] {
            let arguments = approved_arguments().map(|item| {
                if item.starts_with(argument.split('=').next().unwrap()) {
                    argument.to_owned()
                } else {
                    item
                }
            });
            assert!(parse_arguments(arguments).is_err());
        }
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_unsafe_identity() {
        assert!(parse_arguments(std::iter::empty()).is_err());
        assert!(parse_arguments(approved_arguments().chain(["--format=json".to_owned()])).is_err());
        assert!(parse_arguments(approved_arguments().chain(["--other=x".to_owned()])).is_err());
        let unsafe_identity = approved_arguments().map(|item| {
            if item.starts_with("--network-id=") {
                "--network-id=bad\"id".to_owned()
            } else {
                item
            }
        });
        assert!(parse_arguments(unsafe_identity).is_err());
    }
}
