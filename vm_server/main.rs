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

    SshLog {
        event: event,  
        ip: ip.as_str(),
        user: user,
        process: "sshd",
        date: date.as_str(),
        time: time.as_str(),
        hostname: host.trim().to_string(), 
        severity: event_severity(event),
    }
}

fn accepted_connection(line: &str, mut stream: &TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let log = parse_ssh_log(line, "ssh_login");    
    let json = serde_json::to_string_pretty(&log).unwrap();
    println!("{}", json);

    stream.write_all(json.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())

}

fn failed_connection(line: &str) {
    println!("{}", line);
}

fn stream_ssh_logs(stream: TcpStream) -> io::Result<()> {
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

            match caps.as_str() {
                "Accepted" => accepted_connection(&line, &stream).unwrap(),
                "Failed" => failed_connection(&line),
                &_ => println!("No Connections"),
            }
        } else {
            //println!("No Connections");
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
