# Fracture

A high-performance, lightweight rewrite of [GreenTunnel](https://github.com/sadeghhayeri/greentunnel) in Rust.

Fracture is an anti-censorship utility designed to bypass Deep Packet Inspection (DPI) systems used by ISPs to block certain websites. By fragmenting TLS records and manipulating network traffic, it allows you to browse the internet freely and securely.

---

## Why This Rewrite?

The original GreenTunnel is fantastic, but relies on Node.js and Electron—both heavy on system resources. Fracture was built from scratch in Rust to deliver:

- **Zero Dependencies:** Ships as a single, self-contained binary. No Node.js or Electron required.
- **Lightweight & Fast:** Native desktop UI powered by [Dioxus](https://dioxuslabs.com/) with minimal memory footprint.
- **Better Performance:** Significantly faster network stream handling with memory safety guaranteed by Rust.
- **Powerful CLI:** Terminal-first experience with [Clap](https://github.com/clap-rs/clap) for flexible automation.
- **Dual Mode:** Use the GUI for ease or the CLI for headless/server deployments.

---

## Architectural Topology

Fracture is engineered around a **decoupled core server design**. The presentation layers (UI & CLI) are entirely separated from the backend engine, ensuring that network operations remain independent, resilient, and non-blocking.

              ┌──────────────────────────────┐
              │      Fracture Core Engine    │
              │  (Dedicated Native OS Thread)│
              │   └─ Tokio Async Reactor     │
              └──────────────┬───────────────┘
                             │
               ┌─────────────┴─────────────┐
               ▼                           ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │      Desktop UI       │   │          CLI          │
    │   (Dioxus Framework)  │   │     (Clap Parser)     │
    └───────────────────────┘   └───────────────────────┘

- **Isolated Engine Processing:** The proxy server runs on its own native OS thread, spinning up an independent asynchronous Tokio runtime environment. This guarantees zero UI stuttering or terminal latency during heavy network throughput.
- **Unified Frontend Logic:** Both the Desktop app and the CLI interface consume the exact same underlying configuration state maps (`AppConfig`) and background engine handle.

---

## Features

- **DPI Bypass:** Fragments TLS records and evades SNI inspection to bypass Deep Packet Inspection.
- **Modern GUI:** Clean, native desktop interface for configuration and one-click activation.
- **Interactive Terminal Shell:** Full REPL support for headless environments, scripts, and runtime fine-tuning.
- **Ultra-Lightweight:** Blazingly fast with minimal CPU and RAM usage.
- **System Proxy Integration:** Auto-configures OS proxy settings on activation (and reverts on exit).
- **Advanced DNS:** Built-in support for DNS-over-HTTPS with multiple providers.
- **Memory-Safe:** Written in Rust with zero runtime errors.

---

## Installation

### Pre-built Binaries

Download the latest binaries for Windows from [Releases](https://github.com/Yoganand20/fracture/releases).

### Build from Source

Ensure [Rust is installed](https://rustup.rs/).

```bash
git clone https://github.com/Yoganand20/fracture.git
cd fracture
```

Fracture uses strict conditional compilation features to separate the Desktop UI and the Command Line dependencies. Choose your interface below and build the project.

1. **Desktop UI (Dioxus):**
To run or build the desktop application, you will need the dioxus-cli toolchain installed globally.

```bash
dx serve --no-default-features --features desktop
```

1. **Terminal CLI (Clap):**
The CLI client compiles via pure native Cargo without needing any extra external global tooling.

```bash
cargo run --bin fracture-cli --no-default-features --features cli -- [YOUR CLI ARGUMENTS]
```

---

## Usage

### GUI Mode (Desktop)

Launch the application to open the native Dioxus UI:

The interface lets you:

- Configure DNS settings (provider, type, caching)
- Toggle TLS fragmentation and adjust fragment size
- Enable/disable HTTPS-only mode
- Start/stop the proxy with one click
- Monitor proxy status and connection information

### CLI Mode

Perfect for servers, scripts, or automation.

**Start proxy with defaults:**

```bash
fracture start
```

**Start with custom options:**

```bash
fracture --port 9090 --fragment --size 256 --https-only
```

**View all available options:**

```bash
fracture --help
```

**Show version:**

```bash
fracture --version
```

#### CLI Options

| Option | Short | Default | Description |
| -------- | ------- | --------- | ------------- |
| `--port` | `-p` | 8081 | Local proxy port |
| `--fragment` | `-f` | OFF | Enable TLS record fragmentation |
| `--size` | `-s` | 100 | Fragment size in bytes |
| `--https-only` | — | OFF | Only proxy HTTPS traffic |
| `--help` | `-h` | — | Print terminal help and usage information |
| `--version` | `-V` | — | Print application version |

---

## Building for release

### Desktop Binary

```bash
dx build --release --no-default-features --features desktop
./target/release/fracture
```

### CLI Binary

```bash
cargo build --release --bin fracture-cli --no-default-features --features cli
./target/release/fracture --help
```

## Acknowledgments

This project is inspired by the original [GreenTunnel](https://github.com/sadeghhayeri/greentunnel) by Sadegh Hayeri.

---

## Legal Notice

Fracture is designed for legitimate privacy and anti-censorship use in regions with unreasonable internet restrictions. Users are responsible for complying with local laws and regulations. Misuse for malicious purposes is prohibited.
