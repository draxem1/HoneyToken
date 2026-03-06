// host server
use regex::Regex;
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;

fn get_ip() -> String {
    // Matches an octet (0-255)
    let octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    // Matches a full IPv4 address using the octet pattern
    let re = Regex::new(&format!(
        r"\b({})\.({})\.({})\.({})\b",
        octet, octet, octet, octet
    ))
    .unwrap();

    let output = Command::new("ip")
        .arg("a")
        .output()
        .expect("Failed to get IP");

    let mut ips = Vec::new();
    if output.status.success() {
        let stdout = str::from_utf8(&output.stdout).expect("Not valid UTF-8");

        for ipv4 in re.find_iter(stdout) {
            ips.push(ipv4.as_str());
        }
    } else {
        let stderr = str::from_utf8(&output.stderr).expect("Not valid UTF-8");
        eprintln!("Command failed with error:\n{}", stderr);
    }

    //Skip localhost and get your Ip
    String::from(ips[1])
}

fn main() -> std::io::Result<()> {
    let ip = get_ip();
    //Listen on available port
    let listener = TcpListener::bind("0.0.0.0:8080")?;

    println!("Server Listening on 0.0.0.0:8080");
    println!("Set vm server on {}", ip);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("Client connected!");
                let mut buffer = String::new();
                //Read the data sent from the VM client
                stream.read_to_string(&mut buffer)?;
                println!("Recieved data: {}", buffer);
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    Ok(())
}
