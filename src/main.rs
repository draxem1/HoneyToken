use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, BufReader};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct SshLog {
    event: String,
    ip: String,
    user: String,
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
