#!/bin/bash
sudo chmod +x /home/ariel/Documents/github/Firewall/FirewallService/run.sh
# Load user environment
source ~/.bashrc

# Ensure .NET root is correctly set
export DOTNET_ROOT="/home/ariel/.dotnet"
export PATH="$PATH:$DOTNET_ROOT"

# Define your project path and port for gdbserver
APP_PATH="/home/ariel/Documents/github/Firewall/FirewallService/FirewallService/bin/Debug/net8.0/FirewallService.dll"
GDBSERVER_PORT=1234

# Start gdbserver with dotnet command
echo "Starting gdbserver on port $GDBSERVER_PORT..."
sudo gdbserver :$GDBSERVER_PORT /home/ariel/.dotnet/dotnet $APP_PATH &

# Give gdbserver some time to start
sleep 2

# Attach Rider backend in headless mode correctly
echo "Attaching Rider backend to gdbserver in headless mode..."
/home/ariel/.cache/JetBrains/RemoteDev/dist/feafa1dbbcac0_JetBrains.Rider-2024.3-aarch64/bin/rider.sh remote-dev attach --host=localhost --port=$GDBSERVER_PORT --args="--headless"
0
