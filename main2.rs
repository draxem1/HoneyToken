use std::net::TcpStream;
use std::io::{self, Write, BufRead, BufReader};
use std::process::{Command, Stdio};

use serde::{Serialize, Deserialize};
use regex::Regex;

enum Connection {
    Active,
    Failed,
}

#[derive(Serialize, Deserialize)]
struct SshLog<'a> {
    connection: &'a str,
    ip: &'a str,
    user: &'a str,
    process: &'a str,
    date: &'a str,
    time: &'a str,
}

/*****
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
********/
fn parse_ssh_log(line: &str) -> SshLog {
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
    SshLog {
        connection: "Accepted",
        ip: ip.as_str(),
        user: user,
        process: "ssh",
        date: date.as_str(),
        time: time.as_str(),
    }
}

fn accepted_connection(line: &str) {
    let log = parse_ssh_log(line);    
    let json = serde_json::to_string_pretty(&log).unwrap();

    println!("{}", json);

    //stream.write_all(json.as_bytes())?;
    //stream.write_all(b"\n")?;
}

fn failed_connection(line: &str) {
    println!("{}", line);
}

fn stream_ssh_logs(mut stream: TcpStream) -> io::Result<()> {
    /*****
    let regex = Regex::new(
        r"(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*for\s+(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ).unwrap();
*****/
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
                "Accepted" => accepted_connection(&line),
                "Failed" => failed_connection(&line),
                &_ => println!("No Connections"),
            }
        } else {
            //println!("No Connections");
        }
/******
        if let Some(log) = parse_ssh_log(&line, &regex) {

            let json = serde_json::to_string_pretty(&log).unwrap();

            println!("{}", json);

            stream.write_all(json.as_bytes())?;
            stream.write_all(b"\n")?;
        }
******/
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
