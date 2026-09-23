# Fast checks

Run the same checks locally and in GitHub Actions:

```bash
./tests/fast
```

The command prints each result and saves logs plus `summary.json` in a temporary directory. Use `--output PATH` to keep results in a chosen directory.

## Requirements

Use Linux with Python 3.11 or later, Node.js 22 or later, Bash, and the libnm/GLib runtime libraries. On Ubuntu, the library package is `libnm0`. On Arch, it is `libnm`. No Python or Node package installation is required.

The runner requires libnm because one backend test parses synthetic keyfiles with the real library. It does not contact NetworkManager. Missing libraries, skipped Python tests, empty Python suites, timeouts, and test failures cause a nonzero exit.

## Coverage

- Python backend and command-line tests
- Installer rollback tests with inert commands
- Unix socket integration tests with simulated host operations
- Traffic helper tests with synthetic counters
- Node model, service, panel, identity, and traffic suites
- Bash, JavaScript, Python, and JSON syntax checks

Each Python suite uses a separate interpreter. A failed check does not prevent the remaining checks from reporting results.

This workflow does not run Quickshell, graphical previews, privileged installation, network namespaces, or the systemd VM. These remain separate test layers. It does not read VPN credentials or connect a tunnel. Syntax checks alone do not validate QML or the complete Omarchy plugin contract.

## GitHub Actions

The `Fast checks` workflow runs on pushes, pull requests, and manual dispatch. It uses an Ubuntu 24.04 hosted runner, Python 3.11, and Node.js 22. Actions use pinned commit IDs. The job has read-only repository permissions and does not persist checkout credentials.

The job has a ten-minute timeout. Each test subprocess has a ninety-second timeout. Failed runs upload logs and a structured summary, when available, with seven-day retention. GitHub keeps setup failures in the job log.

The workflow does not configure branch protection. After a successful GitHub run, select the `Fast checks` check in the repository's required status checks to enforce it before merge.
