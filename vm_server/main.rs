use std::net::TcpStream;
use std::io::{self, Write, BufRead, BufReader};
use std::process::{Command, Stdio};
use serde::{Serialize, Deserialize};
use regex::Regex;

#[derive(Serialize, Deserialize)]
struct SshLog<'a> {
    event: &'a str,
    ip: &'a str,
    user: &'a str,
    process: &'a str,
    mac: String,
    date: &'a str,
    time: &'a str,
    hostname: String,
    severity: &'a str,
}

fn event_severity<'a>(event: &'a str) -> &'a str{
    match event {
        "ssh_login" => "CRITICAL_HONEYPOT_ACCESS",
        _ => "NO_WORRIES",
    } 
}

fn parse_ssh_log<'a>(line: &'a str, event: &'a str) -> SshLog<'a> {
    let date = {
        let re = Regex::new(r"(?P<date>\w+\s+\d+)").unwrap();
        let caps = re.find(line).unwrap();
        caps
    };
    let time = {
        let re = Regex::new(r"(?P<time>\d+:\d+:\d+)").unwrap();
        let caps = re.find(line).unwrap();
        caps
    };
    let user = {
        let re = Regex::new(r"for\s+(?P<user>\w+)").unwrap();
        let mut user_name = "";

        for caps in re.captures_iter(line) {
        // Access the named group "user"
            if let Some(user_match) = caps.name("user") {
               user_name = user_match.as_str();
            } 
        }
        user_name
    };
    let ip = {
        let re = Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+)").unwrap();
        let caps = re.find(line).unwrap();
        caps
    }; 
    let status = Command::new("hostname")
        .output()
        .expect("No Hostname");
    let host = str::from_utf8(&status.stdout).unwrap();

    let mac = {
        let status = Command::new("arp")
            .arg("-a")
            .arg(&ip.as_str())
            .output()
            .expect("Can't get MAC ADDRESS");
        let mac = str::from_utf8(&status.stdout).unwrap();
        let re = Regex::new(r"([0-9A-Fa-f]{2})\:([0-9A-Fa-f]{2})\:([0-9A-Fa-f]{2})\:([0-9A-Fa-f]{2})\:([0-9A-Fa-f]{2})\:([0-9A-Fa-f]{2})").unwrap();
        let caps = re.find(mac).unwrap();
        format!("{}", caps.as_str())
    };

    SshLog {
        event: event,  
        ip: ip.as_str(),
        user: user,
        process: "sshd",
        mac: mac,
        date: date.as_str(),
        time: time.as_str(),
        hostname: host.trim().to_string(), 
        severity: event_severity(event),
    }
}

fn accepted_connection(line: &str) -> String {
    let log = parse_ssh_log(line, "ssh_login");    
    let json = serde_json::to_string_pretty(&log).unwrap();
    json
}

fn failed_connection(line: &str) -> String {
    line.to_string()
}

fn stream_ssh_logs(mut stream: TcpStream) -> io::Result<()> {
    let re = Regex::new(r"(?P<connection>(Accepted|Failed))").unwrap();
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

        if re.is_match(&line){
            let caps = re.find(&line).unwrap();
            let json; 
            
            match caps.as_str() {
                "Accepted" => json = accepted_connection(&line),
                "Failed" => json = failed_connection(&line),
                &_ => json = "".to_string(), 
            }
            println!("{}", &json);

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
