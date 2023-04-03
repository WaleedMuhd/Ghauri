#!/bin/bash

# Create log directory if it doesn't exist
log_dir="logs"
if [[ ! -d "$log_dir" ]]; then
  mkdir "$log_dir"
fi

# Read input file
input_file="input.log"
while read -r event pid ppid tgid command filename args; do
  # Ignore header line
  if [[ "$event" == "EVENT" ]]; then
    continue
  fi

  # Create log file for PID in log directory if it doesn't exist
  log_file="$log_dir/$pid.log"
  if [[ ! -f "$log_file" ]]; then
    touch "$log_file"
  fi

  # Write event to log file
  echo "$event" >> "$log_file"
done < "$input_file"
