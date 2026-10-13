#!/bin/bash

# Define log file path
LOG_FILE="/tmp/auto_start_pan_read_orders.log"

# Get current timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check the status of the command
if [ "$(sh /var/www/html/OS/startup/pan-readOrders status | grep -v Running | wc -l)" -ne 1 ]; then
    # Execute the command
    sh /var/www/html/OS/startup/pan-readOrders start

    # Append timestamp and command result to log file
    echo "$TIMESTAMP - PanReadOrders restarted successfully" >> "$LOG_FILE"
fi
#else
    # Append timestamp and command result to log file
    # echo "$TIMESTAMP - Command already running" >> "$LOG_FILE"
#fi