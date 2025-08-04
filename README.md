# 🛡️ Cyber-Suite

A comprehensive cybersecurity toolkit with both CLI and modern GUI interfaces.

## 🌟 Features

### 🔐 Password Tools
- **Password Generation**: Create secure random passwords with customizable length
- **Password Encryption**: Encrypt passwords using Fernet (AES 128) encryption
- **Password Decryption**: Decrypt previously encrypted passwords
- **Json format documentation**: Export passwords in JSON format for easy storage and retrieval

### 🌐 IP Address Tools
- **IP Generation**: Generate random IPv4 and IPv6 addresses
- **Flag Detection**: Compare generated IPs against known/filtered addresses
- **Bulk Generation**: Generate multiple IPs with detailed reporting

### 🔍 Vulnerability Scanner
- **Port Scanning**: Network port scanning using nmap
- **Service Detection**: Identify running services and versions
- **CVE & CVSS Lookup**: Vulnerability assessment using NVD API

## 🚀 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/DanielUgoAli/Cyber-Suite.git
   cd Cyber-Suite
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install nmap** (for vulnerability scanner):
   - **Windows**: Download from [nmap.org](https://nmap.org/download.html)
   - **Linux**: `sudo apt install nmap` or `sudo yum install nmap`
   - **macOS**: `brew install nmap`

## 🖥️ Usage

### CLI Interface
```bash
python main.py
```

### GUI Interface
```bash
python gui.py
```

Or launch GUI from CLI by selecting option 4.

## 📋 Requirements

- **Python 3.7+**
- **customtkinter** - Modern GUI framework
- **cryptography** - Password encryption
- **python-nmap** - Network scanning
- **requests** - API communication
- **nmap** - Network discovery tool (external)

## 🔧 Optional Configuration

### NVD API Key
For enhanced vulnerability scanning, get a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key):

1. Set environment variable:
   ```bash
   export NVD_API_KEY="your-api-key-here"
   ```

2. Or enter when prompted by the application

## 📸 Screenshots

### CLI Interface
```
============================================================
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
               SECURITY SUITE
============================================================
```

### GUI Interface
Modern dark theme interface with:
- Clean navigation panel
- Organized tool sections
- Real-time results display
- Progress indicators for long operations

## ⚖️ Legal Notice

This tool is designed for:
- **Educational purposes**
- **Authorized security testing**
- **Personal learning and development**

**Important**: Users are responsible for ensuring compliance with applicable laws and regulations. Only use this tool on systems you own or have explicit permission to test.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is open source. Please use responsibly and ethically.

## 👨‍💻 Author and contributor


- GitHub: [@DanielUgoAli](https://github.com/DanielUgoAli)
- GitHub: [@Isaac M.](https://github.com/ski04)
- GitHub: [@Sunday Samuel](https://github.com/sundaysamuel)
- GitHub: [@Abba Yahaya](https://https://github.com/ay-wq0)


## 🆘 Support

If you encounter issues:
1. Check that all dependencies are installed
2. Ensure nmap is properly installed
3. Verify Python version compatibility
4. Check network connectivity for vulnerability scanner

For bugs or feature requests, please open an issue on GitHub.

---

⭐ **Star this project if you find it useful!**
