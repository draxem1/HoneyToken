#!/bin/bash

#This will watch all ssh logs live and output changes to data.txt
xterm -e 'journalctl -u sshd -f >> data.txt'
