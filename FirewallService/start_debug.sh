#!/bin/bash

APP_PATH="/home/ariel/Documents/github/Firewall/FirewallService/FirewallService/bin/Debug/net8.0/FirewallService.dll"
RIDER_PATH="/home/ariel/.cache/JetBrains/RemoteDev/dist/feafa1dbbcac0_JetBrains.Rider-2024.3-aarch64/bin/rider.sh"

# Kill lingering processes
echo "Cleaning up any lingering processes..."
PIDS=$(pgrep -f "dotnet .*${APP_PATH}")
if [ -n "$PIDS" ]; then
    echo "Found existing PIDs: $PIDS. Killing them..."
    echo "$PIDS" | xargs sudo kill -9
fi

# Start the .NET application with sudo privileges via gdbserver
echo "Starting FirewallService with sudo privileges via gdbserver..."
sudo gdbserver :1234 /home/ariel/.dotnet/dotnet "$APP_PATH" &

# Wait for the process to start
sleep 5

# Find the gdbserver PID
echo "Finding PID of the gdbserver process..."
PID=$(pgrep -f "gdbserver .*${APP_PATH}" | head -n 1)

if [ -z "$PID" ]; then
    echo "No running gdbserver process found for ${APP_PATH}. Exiting."
    exit 1
fi

echo "Attaching Rider to gdbserver process with PID: $PID"
/bin/bash "$RIDER_PATH" attach-to-process "$PID" /home/ariel/Documents/github/Firewall/FirewallService/FirewallService.sln
