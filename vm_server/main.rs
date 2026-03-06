use std::net::TcpStream;
use std::io::{self, Write, BufRead, BufReader};
use std::process::{Command, Stdio};

use serde::{Serialize, Deserialize};
use regex::Regex;

#[derive(Serialize, Deserialize)]
struct SshLog {
    ip: String,
    user: String,
    process: String,
    time: String,
}

fn parse_ssh_log(line: &str, re: &Regex) -> Option<SshLog> {
    if let Some(caps) = re.captures(line) {
        Some(SshLog {
            ip: caps["ip"].to_string(),
            user: caps["user"].to_string(),
            process: "sshd".to_string(),
            time: caps["time"].to_string(),
        })
    } else {
        None
    }
}

fn stream_ssh_logs(mut stream: TcpStream) -> io::Result<()> {

    let regex = Regex::new(
        r"(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*for\s+(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ).unwrap();

    let mut child = Command::new("journalctl")
        .arg("-u")
        .arg("ssh")
        .arg("-f")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start journalctl");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    println!("Watching SSH logs in real time...");

    for line in reader.lines() {
        let line = line?;

        if let Some(log) = parse_ssh_log(&line, &regex) {

            let json = serde_json::to_string(&log).unwrap();

            println!("{}", json);

            stream.write_all(json.as_bytes())?;
            stream.write_all(b"\n")?;
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {

    println!("Starting HoneySecret SSH monitor...");

    let stream = TcpStream::connect("10.0.0.210:8080")?;
    println!("Connected to host server!");

    stream_ssh_logs(stream)?;

    Ok(())
}

