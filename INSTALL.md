# Installation Instructions for OpenSSL

## macOS (using Homebrew)
```bash
# Install OpenSSL development libraries
brew install openssl

# Verify installation
pkg-config --libs openssl
```

## Ubuntu/Debian Linux
```bash
# Install OpenSSL development libraries
sudo apt-get update
sudo apt-get install libssl-dev

# Verify installation
pkg-config --libs openssl
```

## CentOS/RHEL/Fedora Linux
```bash
# Install OpenSSL development libraries
sudo yum install openssl-devel
# OR for newer versions:
sudo dnf install openssl-devel

# Verify installation
pkg-config --libs openssl
```

## Windows (WSL or MinGW)
```bash
# If using WSL, follow Ubuntu instructions above
# If using MinGW, install through package manager or download OpenSSL binaries
```

## Verification
After installation, run:
```bash
make clean && make
```

The build should succeed without linker errors.

## Troubleshooting
- If you get "library not found" errors, ensure OpenSSL development headers are installed (not just the runtime)
- On some systems, you may need to set `PKG_CONFIG_PATH` environment variable
- If pkg-config is not available, manually specify library paths in Makefile
