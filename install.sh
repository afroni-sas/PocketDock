#!/bin/sh
# Installs PocketDock on Android (Termux or adb shell) or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/afroni-sas/PocketDock/main/install.sh | sh
#
# Optional settings, through the environment:
#   POCKETDOCK_VERSION           release tag to install, e.g. v0.1.0 (default: latest)
#   POCKETDOCK_INSTALL_DIR       directory for the binary
#   POCKETDOCK_NO_MODIFY_PATH=1  never edit shell startup files
#   POCKETDOCK_RELEASE_URL       download from this base URL instead of GitHub

set -eu

REPO="afroni-sas/PocketDock"

say() {
    printf '%s\n' "$*"
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

detect_abi() {
    case "$(uname -m)" in
        aarch64 | arm64) echo arm64-v8a ;;
        x86_64 | amd64) echo x86_64 ;;
        *) die "unsupported CPU: $(uname -m). PocketDock needs a 64-bit ARM or x86 device." ;;
    esac
}

install_dir() {
    if [ -n "${POCKETDOCK_INSTALL_DIR:-}" ]; then
        echo "$POCKETDOCK_INSTALL_DIR"
        return
    fi
    case "${PREFIX:-}" in
        */com.termux/*)
            # Already on PATH in Termux.
            echo "$PREFIX/bin"
            return
            ;;
    esac
    case "$(id -u)" in
        # adb shell may only run programs from this directory.
        2000) echo /data/local/tmp ;;
        0) echo /usr/local/bin ;;
        *) echo "$HOME/.local/bin" ;;
    esac
}

release_url() {
    if [ -n "${POCKETDOCK_RELEASE_URL:-}" ]; then
        echo "$POCKETDOCK_RELEASE_URL"
    elif [ -n "${POCKETDOCK_VERSION:-}" ]; then
        echo "https://github.com/$REPO/releases/download/$POCKETDOCK_VERSION"
    else
        echo "https://github.com/$REPO/releases/latest/download"
    fi
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "neither curl nor wget is available. In Termux, run: pkg install curl"
    fi
}

# Makes `pdock` a command. Only ever touches a startup file in $HOME.
expose() {
    say "Installed $1/pdock"
    case ":$PATH:" in
        *":$1:"*) return ;;
    esac
    case "$1" in
        "$HOME"/*) ;;
        *)
            say "$1 is not on your PATH. Run it as $1/pdock"
            return
            ;;
    esac
    line="export PATH=\"$1:\$PATH\""
    if [ "${POCKETDOCK_NO_MODIFY_PATH:-}" = 1 ]; then
        say "To use it, add this to your shell startup file: $line"
        return
    fi
    case "${SHELL:-}" in
        *zsh) rc="$HOME/.zshrc" ;;
        *bash) rc="$HOME/.bashrc" ;;
        *) rc="$HOME/.profile" ;;
    esac
    if ! grep -qxF "$line" "$rc" 2>/dev/null; then
        printf '\n%s\n' "$line" >>"$rc"
    fi
    say "Added $1 to PATH in $rc. Open a new shell, or run: $line"
}

# Everything happens in here, so that a download cut off halfway through
# `curl | sh` runs nothing at all.
main() {
    abi=$(detect_abi)
    dir=$(install_dir)
    base=$(release_url)
    name="pdock-android-$abi"

    mkdir -p "$dir" || die "cannot create $dir"
    tmp="$dir/.pocketdock-install.$$"
    trap 'rm -f "$tmp" "$tmp.sums"' EXIT

    say "Downloading $name"
    fetch "$base/$name" "$tmp" || die "could not download $base/$name"
    fetch "$base/SHA256SUMS" "$tmp.sums" || die "could not download $base/SHA256SUMS"

    expected=$(grep " $name\$" "$tmp.sums" | cut -d' ' -f1)
    [ -n "$expected" ] || die "SHA256SUMS has no entry for $name"
    actual=$(sha256sum "$tmp" | cut -d' ' -f1)
    [ "$actual" = "$expected" ] || die "checksum mismatch for $name; nothing was installed"

    chmod 755 "$tmp"
    "$tmp" version >/dev/null 2>&1 || die "the binary cannot run from $dir"
    mv -f "$tmp" "$dir/pdock"

    expose "$dir"
    say "Check what this device allows with: pdock doctor"
}

main "$@"
