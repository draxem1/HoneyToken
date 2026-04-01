use std::process::Stdio;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use regex::Regex;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

//Mar 26 08:09:14 kali sshd-session[12924]: Failed none for invalid user hee from 10.0.0.210 port 59354 ssh2
//
//Mar 26 07:55:22 kali snoopy[6397]: [uid:1000 sid:4907 tty:/dev/pts/2 cwd:/home/hehe filename:/usr/bin/who]: who -muR

#[derive(Serialize, Deserialize)]
struct Event {
    event: String,
    ip: String,
    user: String,
    process: String,
    hostname: String,
    tty: String,
    time: String,
    command: String,
    }

static SSH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<date>\w+{3}\s+\d+\s+\d+\:\d+\:\d+).*(?P<status>Accepted|Failed).*for\s+(?P<user>\w+).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
 .unwrap()
});

static TTY_COMM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<data>\w+{3}\s+\d+\s+\d+\:\d+\d+).*tty\:(?P<tty>\/\w+\/\w+\/\d+).*\:\s+(?P<command>.*)")
    .unwrap()
});

static IP_TTY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r".*(?P<tty>\s+\w+{3}\/\d+)").unwrap()
});

    //
    //get attacker terminal session with script
    //
    //Record: script --timing=timingfile.tm typescript.txt
    //
    //Replay: scriptreplay -t timingfile.tm typescript.txt
    //-q is quiet mode
    //
    //
        
async fn get_tty(ip: &str, re: &Regex) -> String {
    let output = Command::new("who")
        .output()
        .await
        .expect("TTY failed");

    let who = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    for line in who.lines() {

        if line.contains(ip) {
           return match re.captures(line) {
                Some(caps) => caps["tty"].to_string(),
                None => "".to_string(),
            };
        }
    }

    return String::from("Failed to Identify TTY");

}

async fn hostname() -> String {
    let output = Command::new("hostname")
        .output()
        .await
        .expect("hostname failed");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn attack_type(connection: &str, rsa_key: bool) -> String {
    
    match connection {
        "Accepted" => match rsa_key
        {
            true => String::from("PRIVATE_SSH_KEY"),
            false => String::from("LOGGED_INNO_KEY"),
        },
        "Failed" => String::from("FAILED_LOGIN"),
        &_ => String::from(""),
    }
}

fn parse_ssh_log(line: &str, host: &str, re: &Regex) -> Option<Event> {

    let rsa_key = line.contains("RSA");
    if let Some(caps) = re.captures(line) {

        let attack = attack_type(&caps["status"], rsa_key);
        return Some(Event {
            event: attack,
            ip: caps["ip"].to_string(),
            user: caps["user"].to_string(),
            process: "sshd".to_string(),
            hostname: host.to_string(),
            tty: "".to_string(),
            time: caps["date"].to_string(),
            command: "".to_string(),
        });
    }

    None
}

fn parse_commands(line: &str, re: &Regex) -> Option<Event> {

    if let Some(caps) = re.captures(line) {

        return Some(Event {
            event: "COMMAND_EXECUTED".to_string(),
            ip: "".to_string(),
            user: "".to_string(),
            process: "shell".to_string(),
            hostname: "".to_string(),
            tty: caps["tty"].to_string(),
            time: caps["data"].to_string(),
            command: caps["command"].to_string(),
        });
    }

    None
}


async fn ssh_log_task(tx: mpsc::Sender<Event>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let host = hostname().await;

    let mut child = Command::new("journalctl")
        .arg("-u")
        .arg("ssh")
        .arg("-f")
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {

        if let Some(log) = parse_ssh_log(&line, &host, &SSH_RE) {

            let ip = &log.ip;

            let event = Event {
                event: log.event,
                ip: ip.to_string(),
                user: log.user,
                process: log.process,
                hostname: log.hostname,
                tty: get_tty(&log.ip, &IP_TTY).await,
                time: log.time,
                command: log.command,
            };

            tx.send(event).await?;
        }
    }

    Ok(())
}

async fn command_task(tx: mpsc::Sender<Event>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let mut child = Command::new("journalctl")
        .arg("-f")
        .arg("_COMM=zsh")
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();

    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();


    while let Some(line) = lines.next_line().await? {

      if line.contains("/dev/pts/0") {
            continue;
      }
        if let Some(log) = parse_commands(&line, &TTY_COMM) {
            let event = Event {
                event: log.event,
                ip: log.ip, 
                user: log.user, 
                process: log.process, 
                hostname: log.hostname, 
                tty: log.tty, 
                time: log.time,
                command: log.command,
            };

            tx.send(event).await?;
        }
    }

    Ok(())
}

async fn tcp_sender(
    mut rx: mpsc::Receiver<Event>, mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {

    while let Some(event) = rx.recv().await {

        let json = serde_json::to_string(&event)?;

        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel(100);

    let stream = TcpStream::connect("10.0.0.210:8080").await?;

    tokio::spawn(ssh_log_task(tx.clone()));
    tokio::spawn(command_task(tx.clone()));

    tcp_sender(rx, stream).await?;

    Ok(())
}

