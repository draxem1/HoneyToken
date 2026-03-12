//use std::net::TcpStream;
//use std::io::{self, Write, BufRead, BufReader};
//use std::process::{Command, Stdio};
use std::process::Stdio;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use regex::Regex;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};


#[derive(Serialize, Deserialize)]
struct SshLog {
    event: String,
    ip: String,
    user: String,
    process: String,
    hostname: String,
    time: String,
    severity: String,
}

static SSH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<date>\w+{3}\s+\d+\s+\d+\:\d+\:\d+).*(?P<status>Accepted|Failed).*for\s+(?P<user>\w+).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
 .unwrap()
});

async fn hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .await
        .expect("hostname failed");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn parse_ssh_log(line: &str, host: &str, re: &Regex) -> Option<SshLog> {

    if let Some(caps) = re.captures(line) {

        let event = if &caps["status"] == "Accepted" {
            "ssh_login"
        } else {
            "ssh_failed"
        };

        let severity = if event == "ssh_login" {
            "CRITICAL_HONEYPOT_ACCESS"
        } else {
            "LOW"
        };

        return Some(SshLog {
            event: event.to_string(),
            ip: caps["ip"].to_string(),
            user: caps["user"].to_string(),
            process: "sshd".to_string(),
            hostname: host.to_string(),
            time: caps["date"].to_string(),
            severity: severity.to_string(),
        });
    }

    None
}

/***************************************
fn stream_ssh_logs(mut stream: TcpStream) -> io::Result<()> {

    let host = hostname();

    let re = Regex::new(
        r"(?P<date>\w+{3}\s+\d+\s+\d+\:\d+\:\d+).*(?P<status>Accepted|Failed).*for\s+(?P<user>\w+).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ).unwrap();

    let mut child = Command::new("journalctl")
        .arg("-u")
        .arg("ssh")
        .arg("-f")
        .arg("--since")
        .arg("now")
        .stdout(Stdio::piped())
        .spawn()
        .expect("journalctl failed");

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    println!("Watching SSH logs...");

    for line in reader.lines() {

        let line = line?;

        if SSH_RE.is_match(&line) {

            let log = parse_ssh_log(&line, &host, &re); 
            let json = serde_json::to_string_pretty(&log).unwrap();

            println!("{}", json);

            stream.write_all(json.as_bytes())?;
            stream.write_all(b"\n")?;
            stream.flush()?;
        }
    }

    Ok(())
}
**************************************************/

async fn stream_ssh_logs(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {

    let host = hostname().await;

    let mut child = Command::new("journalctl")
        .arg("-u")
        .arg("ssh")
        .arg("-f")
        .arg("--since")
        .arg("now")
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();

    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    println!("Watching SSH logs...");

    while let Some(line) = lines.next_line().await? {

        if SSH_RE.is_match(&line) {

            let log = parse_ssh_log(&line, &host, &SSH_RE);
            let json = serde_json::to_string(&log)?;

            println!("{:#?}", json);

            stream.write_all(json.as_bytes()).await?;
            stream.write_all(b"\n").await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("Starting HoneySecret sensor...");

    let stream = TcpStream::connect("10.0.0.210:8080").await?;
    
    println!("Connected to logging server");

    stream_ssh_logs(stream).await?;

    Ok(())
}

/*************************************
fn main() -> io::Result<()> {

    println!("HoneySecret sensor starting...");

    let stream = TcpStream::connect("10.0.0.210:8080")?;

    println!("Connected to logging server");

    stream_ssh_logs(stream)?;

    Ok(())
}
**************************************/
