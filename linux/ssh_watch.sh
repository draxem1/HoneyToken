#!/bin/bash

# Force line-buffered output
stdbuf -oL sudo bpftrace ./ssh_monitor.bt | while IFS= read -r line; do
    echo "$line"
    
    if [[ "$line" == *"[SUCCESS]"* ]]; then
        # Delay to allow system files (utmp) and logs to update
        sleep 1.5
        
        # 1. Grab the newest SSH session from 'w'
        # -h: no header, -i: show IP instead of hostname
        W_INFO=$(w -hi | grep "pts/" | tail -n 1)
        USER=$(echo "$W_INFO" | awk '{print $1}')
        TTY=$(echo "$W_INFO" | awk '{print $2}')
        IP=$(echo "$W_INFO" | awk '{print $3}')
        
        # 2. Fallback: If 'w' is slow, use 'ss' and 'ps' to find the newest child
        if [ -z "$IP" ] || [ "$IP" == "-" ]; then
            IP=$(ss -tnp state established '( dport = :22 or sport = :22 )' | grep "sshd" | tail -n 1 | awk '{print $4}' | cut -d: -f1)
            USER=$(ps -eo user,tty,comm | grep sshd | grep "pts/" | tail -n 1 | awk '{print $1}')
            TTY=$(ps -eo user,tty,comm | grep sshd | grep "pts/" | tail -n 1 | awk '{print $2}')
        fi
        
        echo -e "\033[1;32m  -> [MATCH] User: ${USER:-unknown} | IP: ${IP:-N/A} | TTY: /dev/${TTY:-N/A}\033[0m"
        
    elif [[ "$line" == *"[FAILED]"* ]]; then
        # Standard journalctl extraction for failures
        LOG=$(sudo journalctl -u sshd -n 10 --no-pager | grep "Failed password" | tail -n 1)
        F_IP=$(echo "$LOG" | grep -oE "[0-9]{1,3}(\.[0-9]{1,3}){3}" | head -n 1)
        F_USER=$(echo "$LOG" | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}')
        
        echo -e "\033[1;31m  -> [BLOCK] User: ${F_USER:-unknown} | IP: ${F_IP:-N/A}\033[0m"
    fi
done

