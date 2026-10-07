#!/usr/bin/env bash
#
# install_agent_deps.sh — prepare the operator machine to build beacon
# agents with TornadoRevC2.
#
# Installs:
#   - Go toolchain 1.21+          (if not already present)
#   - mingw-w64 cross-compilers   (for BOF compilation on Windows targets)
#   - Optional: garble, donut     (for opsec/paranoid profiles)
#   - Pulls the Go module deps    (utls, x/crypto, x/sys)
#
# Idempotent: safe to run multiple times.

set -euo pipefail

need() {
    # need <binary> <package-per-manager>
    command -v "$1" >/dev/null 2>&1
}

say() { printf '\033[96m[*]\033[0m %s\n' "$*"; }
ok()  { printf '\033[92m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[93m[!]\033[0m %s\n' "$*"; }
err() { printf '\033[91m[✗]\033[0m %s\n' "$*"; }

# ---- detect package manager ------------------------------------------------

if [[ "$(uname)" == "Darwin" ]]; then
    PM="brew"
    PM_INSTALL="brew install"
elif [[ -f /etc/debian_version ]]; then
    PM="apt"
    PM_INSTALL="sudo apt-get install -y"
    sudo apt-get update -qq
elif [[ -f /etc/fedora-release ]]; then
    PM="dnf"
    PM_INSTALL="sudo dnf install -y"
elif [[ -f /etc/arch-release ]]; then
    PM="pacman"
    PM_INSTALL="sudo pacman -S --noconfirm"
elif [[ -f /etc/msystem ]] || [[ -d /mingw64 ]]; then
    PM="msys2"
    PM_INSTALL="pacman -S --noconfirm"
else
    err "Unsupported host OS. Install Go 1.21+ manually from https://go.dev/dl/"
    exit 1
fi

say "Host package manager: $PM"

# ---- Go toolchain ----------------------------------------------------------

if need go; then
    GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    ok "Go $GO_VER already installed"
else
    warn "Go not found. Installing..."
    case "$PM" in
        brew)   $PM_INSTALL go ;;
        apt)    $PM_INSTALL golang-go ;;
        dnf)    $PM_INSTALL golang ;;
        pacman) $PM_INSTALL go ;;
        msys2)  $PM_INSTALL mingw-w64-x86_64-go ;;
    esac
    ok "Go installed"
fi

# Verify 1.21+ for utls
GO_MAJOR=$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f1)
GO_MINOR=$(go version | awk '{print $3}' | sed 's/go//' | cut -d. -f2)
if (( GO_MAJOR < 1 )) || (( GO_MAJOR == 1 && GO_MINOR < 24 )); then
    err "Go 1.24+ required (found $GO_MAJOR.$GO_MINOR). Upgrade from https://go.dev/dl/"
    exit 1
fi
ok "Go $GO_MAJOR.$GO_MINOR satisfies 1.24+ requirement"

# ---- mingw-w64 (BOF compilation) -------------------------------------------

case "$PM" in
    apt)
        if ! need x86_64-w64-mingw32-gcc; then
            say "Installing mingw-w64 for BOF compilation..."
            $PM_INSTALL gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
                        gcc-mingw-w64-i686  g++-mingw-w64-i686
        fi
        ;;
    dnf)
        if ! need x86_64-w64-mingw32-gcc; then
            say "Installing mingw-w64 for BOF compilation..."
            $PM_INSTALL mingw64-gcc mingw64-gcc-c++ mingw32-gcc mingw32-gcc-c++
        fi
        ;;
    pacman)
        if ! need x86_64-w64-mingw32-gcc; then
            say "Installing mingw-w64 for BOF compilation..."
            $PM_INSTALL mingw-w64-gcc
        fi
        ;;
    brew)
        if ! need x86_64-w64-mingw32-gcc; then
            say "Installing mingw-w64 for BOF compilation..."
            $PM_INSTALL mingw-w64
        fi
        ;;
    msys2)
        if ! need x86_64-w64-mingw32-gcc; then
            say "Installing mingw-w64 for BOF compilation..."
            $PM_INSTALL mingw-w64-x86_64-gcc mingw-w64-i686-gcc
        fi
        ;;
esac

if need x86_64-w64-mingw32-gcc; then
    ok "mingw-w64 (x64 + x86) available"
else
    warn "mingw-w64 not on PATH — BOF source compilation will not work. Pre-built .o files still load."
fi

# ---- optional: garble, donut -----------------------------------------------

GOPATH_BIN="$(go env GOPATH)/bin"

if ! need garble; then
    say "Installing garble (used by opsec/paranoid profiles)..."
    if go install mvdan.cc/garble@latest 2>/dev/null; then
        ok "garble installed to $GOPATH_BIN/garble"
        warn "Ensure $GOPATH_BIN is on PATH: export PATH=\"\$PATH:$GOPATH_BIN\""
    else
        warn "garble install failed — opsec/paranoid profiles will not build. Others still work."
    fi
else
    ok "garble already installed"
fi

if ! need donut; then
    warn "Donut not found — 'shellcode' output format will not work."
    warn "Download from: https://github.com/TheWover/donut/releases"
    warn "Or place at agent/embed/bin/donut"
else
    ok "donut available"
fi

if ! need upx; then
    warn "UPX not found — the paranoid profile's UPX packing will be skipped."
    case "$PM" in
        apt)    $PM_INSTALL upx-ucl ;;
        dnf)    $PM_INSTALL upx ;;
        pacman) $PM_INSTALL upx ;;
        brew)   $PM_INSTALL upx ;;
    esac
else
    ok "UPX available"
fi

# ---- Go module dependencies ------------------------------------------------

# Find the agent directory: prefer ./agent/, then ./tornadorevc2/agent/.
if [[ -f ./agent/go.mod ]]; then
    AGENT_DIR=./agent
elif [[ -f ./tornadorevc2/agent/go.mod ]]; then
    AGENT_DIR=./tornadorevc2/agent
elif [[ -n "${TORNADOREVC2_AGENT_DIR:-}" && -f "$TORNADOREVC2_AGENT_DIR/go.mod" ]]; then
    AGENT_DIR="$TORNADOREVC2_AGENT_DIR"
else
    err "Cannot find agent/go.mod — run this script from the repo root."
    exit 1
fi

say "Agent directory: $AGENT_DIR"

pushd "$AGENT_DIR" >/dev/null
say "Pulling Go module dependencies (utls, x/crypto, x/sys)..."
if go mod download; then
    ok "Module cache populated"
else
    err "go mod download failed. If you are behind a proxy, set HTTPS_PROXY."
    popd >/dev/null
    exit 1
fi

# Verify utls is resolvable
if go list -m github.com/refraction-networking/utls >/dev/null 2>&1; then
    UTLS_VER=$(go list -m github.com/refraction-networking/utls | awk '{print $2}')
    ok "utls $UTLS_VER available"
else
    say "Adding utls to the module graph..."
    go get github.com/refraction-networking/utls@latest
    go mod tidy
    ok "utls added"
fi

# ---- smoke test ------------------------------------------------------------

say "Running a smoke build of the agent (both targets)..."
if GOOS=linux GOARCH=amd64 go build -o /tmp/_beacon_dep_check .; then
    ok "Linux build succeeded"
    rm -f /tmp/_beacon_dep_check
else
    err "Linux build failed. Review the output above."
    popd >/dev/null
    exit 1
fi

if GOOS=windows GOARCH=amd64 go build -o /tmp/_beacon_dep_check.exe .; then
    ok "Windows build succeeded"
    rm -f /tmp/_beacon_dep_check.exe
else
    err "Windows build failed. Review the compiler output above."
    err "If the error mentions 'no matching files for pattern embed/...', then"
    err "one of the C# source files under agent/embed/ is missing."
    popd >/dev/null
    exit 1
fi

popd >/dev/null

# ---- Python handler deps (for completeness) --------------------------------

say "Checking Python handler dependencies..."
for pkg in flask cryptography; do
    if python3 -c "import $pkg" 2>/dev/null; then
        ok "python3 -c 'import $pkg' OK"
    else
        warn "$pkg not installed. Run: pip3 install $pkg"
    fi
done

if python3 -c "import h2" 2>/dev/null; then
    ok "python3 -c 'import h2' OK (shell handler HTTPS transport)"
else
    warn "h2 not installed. HTTPS secondary transport for shell sessions will not start."
    warn "Run: pip3 install h2"
fi

if python3 -c "import smbprotocol" 2>/dev/null; then
    ok "python3 -c 'import smbprotocol' OK (shell handler SMB transport)"
else
    warn "smbprotocol not installed. smbswitch/smblateral will not work."
    warn "Run: pip3 install smbprotocol"
fi

echo
ok "Agent dependency installation complete."
echo
echo "Next steps:"
echo "  1. Ensure $GOPATH_BIN is on PATH:"
echo "       export PATH=\"\$PATH:$GOPATH_BIN\""
echo "  2. From the handler prompt:"
echo "       tornado> beacon-build linux amd64 --profile stealth --c2-profile chrome"
echo "  3. Compiled agents appear in beacon_output/"