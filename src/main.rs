use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, BufReader};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct SshLog {
    event: String,
    ip: String,
    user: String,use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, BufReader};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::sync::Mutex;

static BRUTE_DATA: LazyLock<Mutex<HashMap<String, u32>>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("0.0.0.0".to_string(), 10);
    Mutex::new(m)
});

#[derive(Debug, Serialize, Deserialize)]
struct SshLog {
    event: String,
    ip: String,
    user: String,
    process: String,
    hostname: String,
    time: String,
}

fn brute_force(attacker: &SshLog) -> bool{

    let mut bfd = false;
    let mut data = BRUTE_DATA.lock().unwrap();

    if data.contains_key(&attacker.ip) {

        if let Some(attempts) = data.get_mut(&attacker.ip) {
            *attempts += 1;
            
            if *attempts > 5 {
                bfd = true;
            }
        };
    }
    else {
        data.insert(attacker.ip.clone(), 1);
    }
    bfd
}

async fn detect_attack(log: &SshLog) {
    
    let bfd = brute_force(log);

    let print_profile = |log: &SshLog|
        println!(
            "Host: {} \nUser: {} \nAttacker IP: {} \nProcess: {} \nTime: {}",
            log.hostname,
            log.user,
            log.ip,
            log.process,
            log.time,
        );
    if log.event == "PRIVATE_SSH_KEY" {

        println!("\n🚨 CRITICAL ALERT 🚨 --- PRIVATE KEY LOGIN");
        print_profile(log);
    }
    else if log.event == "LOGGED_INNO_KEY" && bfd {
        println!("\n🚨 CRITICAL ALERT 🚨 --- BRUTE FORCE LOGIN");
        print_profile(log);
    }
    else if log.event == "FAILED_LOGIN" && bfd {
        println!("\n🚨 MEDIUM LEVEL ALERT 🚨 --- BRUTE FORCE ATTEMPT");
        print_profile(log);
    }
    else {
        println!("FAILED LOGIN");
    }
}

async fn handle_client(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {

    let addr = stream.peer_addr()?;
    println!("Sensor connected: {}", addr);

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {

        match serde_json::from_str::<SshLog>(&line) {

            Ok(log) => {

                detect_attack(&log).await;
            }

            Err(_) => {
                println!("Malformed telemetry: {}", line);
            }
        }
    }

    println!("Sensor disconnected: {}", addr);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    println!("HoneySecret Logging Server Running");
    println!("Listening on port 8080\n");

    loop {

        let (stream, addr) = listener.accept().await?;

        println!("Incoming sensor: {}", addr);

        tokio::spawn(async move {

            if let Err(e) = handle_client(stream).await {
                println!("Client error: {}", e);
            }

        });
    }
}

    process: String,
    hostname: String,
    severity: String,
}

async fn detect_attack(log: &SshLog) {

    if log.severity == "CRITICAL_HONEYPOT_ACCESS" {
        println!(
            "\n🚨 CRITICAL ALERT 🚨
Host: {}
User: {}
Attacker IP: {}
Process: {}
",
            log.hostname,
            log.user,
            log.ip,
            log.process
        );
    }
}

async fn handle_client(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {

    let addr = stream.peer_addr()?;
    println!("Sensor connected: {}", addr);

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {

        match serde_json::from_str::<SshLog>(&line) {

            Ok(log) => {

                println!("Event: {:?}", log);

                detect_attack(&log).await;
            }

            Err(_) => {
                println!("Malformed telemetry: {}", line);
            }
        }
    }

    println!("Sensor disconnected: {}", addr);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    println!("HoneySecret Logging Server Running");
    println!("Listening on port 8080\n");

    loop {

        let (stream, addr) = listener.accept().await?;

        println!("Incoming sensor: {}", addr);

        tokio::spawn(async move {

            if let Err(e) = handle_client(stream).await {
                println!("Client error: {}", e);
            }

        });
    }
}
