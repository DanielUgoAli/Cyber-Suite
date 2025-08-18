#!/bin/bash

# Cyber-Suite Installer for Linux/macOS
echo "Cyber-Suite Installer"
echo "====================="

# Check for Git
if ! command -v git &> /dev/null; then
    echo "Error: Git is not installed."
    echo "Please install Git before continuing:"
    echo "  - For Ubuntu/Debian: sudo apt install git"
    echo "  - For Fedora/RHEL: sudo dnf install git"
    echo "  - For macOS: brew install git"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed."
    echo "Please install Python 3 before continuing:"
    echo "  - For Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  - For Fedora/RHEL: sudo dnf install python3 python3-pip"
    echo "  - For macOS: brew install python"
    exit 1
fi

# Set installation directory
INSTALL_DIR="$HOME/.local/share/Cyber-Suite"

# Create installation directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

echo "Installing Cyber-Suite to $INSTALL_DIR..."

# Clone repository
echo "Cloning repository..."
git clone https://github.com/DanielUgoAli/Cyber-Suite.git "$INSTALL_DIR"
if [ $? -ne 0 ]; then
    echo "Failed to clone repository."
    exit 1
fi

# Install requirements
echo "Installing Python requirements..."
cd "$INSTALL_DIR"
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Warning: Failed to install some requirements."
    echo "You may need to install them manually."
fi

# Create launcher script
echo "Creating launcher script..."
LAUNCHER="$INSTALL_DIR/cybersuite.sh"
cat > "$LAUNCHER" << 'EOL'
#!/bin/bash
cd "$(dirname "$0")"
python3 gui.py
EOL
chmod +x "$LAUNCHER"

# Create desktop shortcut
echo "Creating desktop shortcut..."
DESKTOP_DIR="$HOME/Desktop"
DESKTOP_FILE="$DESKTOP_DIR/Cyber-Suite.desktop"

if [ -d "$DESKTOP_DIR" ]; then
    cat > "$DESKTOP_FILE" << EOL
[Desktop Entry]
Type=Application
Name=Cyber-Suite
Exec=$LAUNCHER
Icon=utilities-terminal
Comment=Cybersecurity Toolkit
Terminal=false
Categories=Utility;Security;
EOL
    chmod +x "$DESKTOP_FILE"
else
    echo "Desktop directory not found. Skipping desktop shortcut creation."
fi

# Create application menu entry
echo "Creating application menu entry..."
APP_DIR="$HOME/.local/share/applications"
APP_FILE="$APP_DIR/Cyber-Suite.desktop"

mkdir -p "$APP_DIR"
cat > "$APP_FILE" << EOL
[Desktop Entry]
Type=Application
Name=Cyber-Suite
Exec=$LAUNCHER
Icon=utilities-terminal
Comment=Cybersecurity Toolkit
Terminal=false
Categories=Utility;Security;
EOL
chmod +x "$APP_FILE"

echo ""
echo "Installation completed successfully!"
echo "Cyber-Suite has been installed to $INSTALL_DIR"
echo "You can launch it from your applications menu or desktop shortcut."
echo "Or run it directly with: $LAUNCHER"
echo ""

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Note: nmap is not installed on your system."
    echo "For full functionality of the vulnerability scanner, please install nmap:"
    echo "  - For Ubuntu/Debian: sudo apt install nmap"
    echo "  - For Fedora/RHEL: sudo dnf install nmap"
    echo "  - For macOS: brew install nmap"
fi
