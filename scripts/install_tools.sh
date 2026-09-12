#!/usr/bin/env bash
set -euo pipefail

echo "=== CodeGuard tool installer ==="
echo "Installing Trivy and Gitleaks..."
echo

OS="$(uname -s)"

check_winget() {
    if ! command -v winget.exe &> /dev/null; then
        echo "winget.exe not found. Install 'App Installer' from the Microsoft Store, then re-run this script."
        echo "https://apps.microsoft.com/detail/9nblggh4nns1"
        exit 1
    fi
}

install_trivy() {
    if command -v trivy &> /dev/null; then
        echo "Trivy already installed: $(trivy --version | head -n 1)"
        return
    fi

    echo "Installing Trivy..."
    case "$OS" in
        Linux)
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
                | sh -s -- -b /usr/local/bin
            ;;
        Darwin)
            if command -v brew &> /dev/null; then
                brew install trivy
            else
                echo "Homebrew not found. Install it first: https://brew.sh"
                exit 1
            fi
            ;;
        MINGW*|MSYS*)
            echo "Detected Git Bash on Windows — using winget..."
            check_winget
            winget.exe install --id AquaSecurity.Trivy --accept-source-agreements --accept-package-agreements
            echo "Note: you may need to restart this terminal for 'trivy' to be found on PATH."
            ;;
        *)
            echo "Unsupported OS for automatic Trivy install: $OS"
            echo "See https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            exit 1
            ;;
    esac
}

install_gitleaks() {
    if command -v gitleaks &> /dev/null; then
        echo "Gitleaks already installed: $(gitleaks version)"
        return
    fi

    echo "Installing Gitleaks..."
    case "$OS" in
        Linux)
            GITLEAKS_VERSION=$(curl -sL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
                | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
            curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
                -o /tmp/gitleaks.tar.gz
            tar -xzf /tmp/gitleaks.tar.gz -C /tmp
            sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
            rm /tmp/gitleaks.tar.gz
            ;;
        Darwin)
            if command -v brew &> /dev/null; then
                brew install gitleaks
            else
                echo "Homebrew not found. Install it first: https://brew.sh"
                exit 1
            fi
            ;;
        MINGW*|MSYS*)
            echo "Detected Git Bash on Windows — using winget..."
            check_winget
            winget.exe install --id Gitleaks.Gitleaks --accept-source-agreements --accept-package-agreements
            echo "Note: you may need to restart this terminal for 'gitleaks' to be found on PATH."
            ;;
        *)
            echo "Unsupported OS for automatic Gitleaks install: $OS"
            echo "See https://github.com/gitleaks/gitleaks#installing"
            exit 1
            ;;
    esac
}

install_trivy
install_gitleaks

echo
echo "=== Verifying installations ==="
command -v trivy &> /dev/null && echo "✓ trivy: $(trivy --version | head -n 1)" || echo "✗ trivy not found (restart this terminal if you just installed via winget)"
command -v gitleaks &> /dev/null && echo "✓ gitleaks: $(gitleaks version)" || echo "✗ gitleaks not found (restart this terminal if you just installed via winget)"

echo
echo "Note: Semgrep is installed via pip as part of the project's Python dependencies."
echo "Run 'pip install -e .' (or your usual install command) if you haven't already."