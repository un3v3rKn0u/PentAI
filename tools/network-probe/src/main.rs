use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

struct Arguments {
    network_id: String,
    direct_ip: IpAddr,
    dns_ip: IpAddr,
    ipv6: IpAddr,
}

fn main() {
    let raw_arguments: Vec<String> = env::args().skip(1).collect();
    if let Some(runtime_id) = sentinel_runtime_id(&raw_arguments) {
        run_sentinel(runtime_id);
    }
    if raw_arguments == ["--mode=http-fixture-server"] {
        run_http_fixture_server();
    }
    if raw_arguments.first().map(String::as_str) == Some("--mode=http-fixture-client") {
        match parse_http_fixture_client(&raw_arguments).and_then(run_http_fixture_client) {
            Ok(result) => {
                println!(
                    concat!(
                        "{{\"outcome\":\"{}\",",
                        "\"observed_response_bytes\":{},",
                        "\"retained_response_bytes\":{}}}"
                    ),
                    result.outcome, result.observed, result.retained
                );
                return;
            }
            Err(message) => {
                eprintln!("pentai-network-probe: {message}");
                process::exit(2);
            }
        }
    }
    let arguments = match parse_arguments(raw_arguments.into_iter()) {
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

struct HttpFixtureArguments {
    maximum_response_bytes: usize,
    deadline_unix_milliseconds: u128,
}

struct HttpFixtureResult {
    outcome: &'static str,
    observed: usize,
    retained: usize,
}

fn parse_http_fixture_client(arguments: &[String]) -> Result<HttpFixtureArguments, &'static str> {
    let mut target = false;
    let mut mode = false;
    let mut host = false;
    let mut path = false;
    let mut maximum_response_bytes = None;
    let mut deadline_unix_milliseconds = None;
    for argument in arguments {
        match argument.as_str() {
            "--mode=http-fixture-client" if !mode => mode = true,
            "--target=192.0.2.20:8080" if !target => target = true,
            "--host=example.test" if !host => host = true,
            "--path=/fixture" if !path => path = true,
            value if value.starts_with("--maximum-response-bytes=") => {
                if maximum_response_bytes.is_some() {
                    return Err("duplicate response limit");
                }
                maximum_response_bytes = value
                    .strip_prefix("--maximum-response-bytes=")
                    .and_then(|raw| raw.parse::<usize>().ok())
                    .filter(|value| (1..=1_048_576).contains(value));
            }
            value if value.starts_with("--deadline-unix-milliseconds=") => {
                if deadline_unix_milliseconds.is_some() {
                    return Err("duplicate deadline");
                }
                deadline_unix_milliseconds = value
                    .strip_prefix("--deadline-unix-milliseconds=")
                    .and_then(|raw| raw.parse::<u128>().ok())
                    .filter(|value| *value > 0);
            }
            _ => return Err("unsupported or duplicate HTTP fixture argument"),
        }
    }
    match (
        target,
        mode,
        host,
        path,
        maximum_response_bytes,
        deadline_unix_milliseconds,
    ) {
        (true, true, true, true, Some(limit), Some(deadline)) => Ok(HttpFixtureArguments {
            maximum_response_bytes: limit,
            deadline_unix_milliseconds: deadline,
        }),
        _ => Err("required HTTP fixture argument is missing or invalid"),
    }
}

fn run_http_fixture_client(
    arguments: HttpFixtureArguments,
) -> Result<HttpFixtureResult, &'static str> {
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HTTP fixture clock is invalid")?
        .as_millis();
    let remaining_milliseconds = arguments
        .deadline_unix_milliseconds
        .checked_sub(wall_now)
        .filter(|value| (1..=5_000).contains(value))
        .ok_or("HTTP fixture deadline is invalid")?;
    let started = Instant::now();
    let deadline = started
        + Duration::from_millis(
            remaining_milliseconds
                .try_into()
                .map_err(|_| "HTTP fixture deadline is invalid")?,
        );
    let address = "192.0.2.20:8080"
        .parse::<SocketAddr>()
        .map_err(|_| "fixed fixture address is invalid")?;
    let mut stream = loop {
        let Some(available) = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
        else {
            return Ok(failure_result(started, deadline, 0));
        };
        let attempt = available.min(Duration::from_millis(100));
        match TcpStream::connect_timeout(&address, attempt) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => {
                let pause = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default()
                    .min(Duration::from_millis(10));
                thread::sleep(pause);
            }
            Err(_) => return Ok(failure_result(started, deadline, 0)),
        }
    };
    if Instant::now() >= deadline {
        return Ok(failure_result(started, deadline, 0));
    }
    apply_timeout(&stream, deadline)?;
    let request = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).is_err() {
        return Ok(failure_result(started, deadline, 0));
    }
    let mut header = Vec::new();
    let mut one_byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if Instant::now() >= deadline {
            return Ok(failure_result(started, deadline, 0));
        }
        apply_timeout(&stream, deadline)?;
        match stream.read(&mut one_byte) {
            Ok(0) => {
                return Ok(HttpFixtureResult {
                    outcome: "transport_error",
                    observed: 0,
                    retained: 0,
                })
            }
            Ok(_) => header.push(one_byte[0]),
            Err(_) => return Ok(failure_result(started, deadline, 0)),
        }
        if header.len() > 8_192 {
            return Err("HTTP fixture headers exceeded the hard limit");
        }
    }
    let content_length = parse_fixture_headers(&header)?;
    let mut body_seen = 0usize;
    let mut body_retained = 0usize;
    let mut buffer = [0u8; 1024];
    loop {
        if Instant::now() >= deadline {
            return Ok(failure_result(started, deadline, body_seen));
        }
        apply_timeout(&stream, deadline)?;
        let remaining_proof = arguments.maximum_response_bytes + 1 - body_seen;
        let read_bound = buffer.len().min(remaining_proof);
        let read = match stream.read(&mut buffer[..read_bound]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return Ok(failure_result(started, deadline, body_seen)),
        };
        body_seen += read;
        body_retained = body_seen.min(arguments.maximum_response_bytes);
        if body_seen > arguments.maximum_response_bytes {
            return Ok(HttpFixtureResult {
                outcome: if Instant::now() >= deadline {
                    "deadline_exceeded"
                } else {
                    "response_limit_exceeded"
                },
                observed: arguments.maximum_response_bytes + 1,
                retained: arguments.maximum_response_bytes,
            });
        }
    }
    if Instant::now() >= deadline {
        return Ok(HttpFixtureResult {
            outcome: "deadline_exceeded",
            observed: body_seen,
            retained: body_retained,
        });
    }
    if content_length != body_seen {
        return Ok(HttpFixtureResult {
            outcome: "transport_error",
            observed: body_seen,
            retained: body_retained,
        });
    }
    Ok(HttpFixtureResult {
        outcome: "completed",
        observed: body_seen,
        retained: body_retained,
    })
}

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or("HTTP fixture deadline expired")
}

fn apply_timeout(stream: &TcpStream, deadline: Instant) -> Result<(), &'static str> {
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| "HTTP fixture timeout could not be applied")
}

fn failure_result(started: Instant, deadline: Instant, observed: usize) -> HttpFixtureResult {
    HttpFixtureResult {
        outcome: if Instant::now() >= deadline && deadline > started {
            "deadline_exceeded"
        } else {
            "transport_error"
        },
        observed,
        retained: observed,
    }
}

fn parse_fixture_headers(header: &[u8]) -> Result<usize, &'static str> {
    let text = std::str::from_utf8(header).map_err(|_| "HTTP fixture headers are invalid")?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("HTTP fixture status is invalid");
    }
    let mut content_length = None;
    let mut connection_close = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("HTTP fixture header is malformed");
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err("HTTP fixture header is malformed");
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("HTTP fixture transfer encoding is unsupported");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("HTTP fixture content length is ambiguous");
            }
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("connection") {
            if connection_close || !value.trim().eq_ignore_ascii_case("close") {
                return Err("HTTP fixture connection framing is invalid");
            }
            connection_close = true;
        } else {
            return Err("HTTP fixture header is unsupported");
        }
    }
    if !connection_close {
        return Err("HTTP fixture connection framing is missing");
    }
    content_length.ok_or("HTTP fixture content length is missing")
}

fn run_http_fixture_server() -> ! {
    let listener = TcpListener::bind("0.0.0.0:8080").unwrap_or_else(|_| process::exit(2));
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
        let mut request = Vec::new();
        let mut buffer = [0u8; 128];
        while request.len() <= 256 && !request.ends_with(b"\r\n\r\n") {
            let Ok(read) = stream.read(&mut buffer) else {
                break;
            };
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let expected = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
        if request != expected {
            continue;
        }
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\npentai-fixture-ok";
        let _ = stream.write_all(response);
    }
    process::exit(0)
}

fn sentinel_runtime_id(arguments: &[String]) -> Option<&str> {
    match arguments {
        [mode, runtime] if mode == "--mode=sentinel" => runtime
            .strip_prefix("--runtime-id=")
            .filter(|value| valid_identifier(value)),
        _ => None,
    }
}

fn run_sentinel(_runtime_id: &str) -> ! {
    loop {
        thread::sleep(Duration::from_secs(60));
    }
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

    #[test]
    fn sentinel_mode_requires_only_a_safe_runtime_identity() {
        let valid = [
            "--mode=sentinel".to_owned(),
            "--runtime-id=runtime-1".to_owned(),
        ];
        assert_eq!(sentinel_runtime_id(&valid), Some("runtime-1"));
        assert_eq!(sentinel_runtime_id(&valid[..1]), None);
        assert_eq!(
            sentinel_runtime_id(&[
                "--mode=sentinel".to_owned(),
                "--runtime-id=bad/id".to_owned()
            ]),
            None
        );
    }

    #[test]
    fn fixture_client_accepts_only_the_owned_test_net_tuple() {
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock")
            .as_millis()
            + 1_000;
        let approved = vec![
            "--mode=http-fixture-client".to_owned(),
            "--target=192.0.2.20:8080".to_owned(),
            "--host=example.test".to_owned(),
            "--path=/fixture".to_owned(),
            "--maximum-response-bytes=1024".to_owned(),
            format!("--deadline-unix-milliseconds={deadline}"),
        ];
        let parsed = parse_http_fixture_client(&approved).expect("approved fixture request");
        assert_eq!(parsed.maximum_response_bytes, 1024);
        assert!(run_http_fixture_client(HttpFixtureArguments {
            maximum_response_bytes: 1024,
            deadline_unix_milliseconds: deadline + 6_000,
        })
        .is_err());
        for denied in [
            "--target=127.0.0.1:8080",
            "--target=192.0.2.21:8080",
            "--host=other.test",
            "--path=/other",
            "--maximum-response-bytes=0",
            "--deadline-unix-milliseconds=0",
        ] {
            let prefix = denied.split('=').next().expect("argument prefix");
            let changed = approved
                .iter()
                .map(|value| {
                    if value.starts_with(prefix) {
                        denied.to_owned()
                    } else {
                        value.clone()
                    }
                })
                .collect::<Vec<_>>();
            assert!(parse_http_fixture_client(&changed).is_err());
        }
        let duplicated_mode = approved
            .iter()
            .cloned()
            .chain(["--mode=http-fixture-client".to_owned()])
            .collect::<Vec<_>>();
        assert!(parse_http_fixture_client(&duplicated_mode).is_err());
        let unknown = approved
            .iter()
            .cloned()
            .chain(["--other=value".to_owned()])
            .collect::<Vec<_>>();
        assert!(parse_http_fixture_client(&unknown).is_err());
    }

    #[test]
    fn fixture_headers_require_unambiguous_length_and_status() {
        assert_eq!(
            parse_fixture_headers(
                b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n"
            ),
            Ok(17)
        );
        for denied in [
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Other: value\r\n\r\n".as_slice(),
        ] {
            assert!(parse_fixture_headers(denied).is_err());
        }
    }
}
