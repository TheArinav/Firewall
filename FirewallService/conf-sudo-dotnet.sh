#!/bin/bash

# Get the full path to dotnet
DOTNET_PATH=$(which dotnet)

# Use sudo with the full dotnet path
sudo $DOTNET_PATH "/home/ariel/Documents/github/Firewall/FirewallService/bin/Debug/net8.0/FirewallService.dll"
