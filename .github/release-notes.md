## Install

In Termux, or on Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/main/install.sh | sh
```

Or download the binary for your device:

| Device | File |
|---|---|
| Phones and tablets (64-bit ARM) | `pdock-android-arm64-v8a` |
| Emulators and x86 devices | `pdock-android-x86_64` |

## Verify

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

Built from commit ${GITHUB_SHA} by [this workflow run](${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}).
