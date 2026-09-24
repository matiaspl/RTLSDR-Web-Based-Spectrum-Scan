#!/bin/bash
# ==============================================================================
# RTL-SDR Web Spectrum Scanner - Mac First-Launch & Run Script
# ==============================================================================

cd "$(dirname "$0")"

echo ""
echo "=================================================================="
echo "   RTL-SDR Web Spectrum Scanner Launcher"
echo "=================================================================="
echo ""

# 1. Check for Node.js
if ! command -v node >/dev/null 2>&1; then
    echo "[!] Node.js was not found on your system."
    echo ""
    
    if command -v brew >/dev/null 2>&1; then
        read -p "--> Would you like to install Node.js automatically via Homebrew? (y/n): " choice
        case "$choice" in 
            y|Y ) 
                echo "Installing Node.js..."
                brew install node
                ;;
            * ) 
                echo "Opening Node.js download page in your browser..."
                open "https://nodejs.org/"
                echo "Please download and install the LTS version, then double-click this script again."
                read -p "Press [Enter] to exit..."
                exit 1
                ;;
        esac
    else
        echo "Opening the official Node.js download page in your web browser..."
        open "https://nodejs.org/"
        echo ""
        echo "Please download and run the macOS installer (.pkg), then re-launch this script."
        echo ""
        read -p "Press [Enter] to exit..."
        exit 1
    fi
fi

NODE_VERSION=$(node -v)
echo "[✓] Node.js is ready: $NODE_VERSION"

# 2. Check for Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 was not found. macOS usually includes Python or prompts for Command Line Tools."
    echo "    Opening python.org download page..."
    open "https://www.python.org/downloads/"
    read -p "Press [Enter] to exit..."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "[✓] Python is ready: $PYTHON_VERSION"
echo ""

# 3. Open browser after a brief startup delay
(
    sleep 2
    open "http://localhost:8080"
) &

# 4. Start Server
echo "Starting RTL-SDR Web Spectrum Application..."
echo "Access on this Mac: http://localhost:8080"
echo "Access on iPad/LAN: http://$(hostname):8080 or http://<Your-Mac-IP>:8080"
echo ""
echo "Press Ctrl+C to stop the server."
echo "=================================================================="
echo ""

node server.js
