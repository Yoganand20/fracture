# 🔒 Fracture

A high-performance, lightweight rewrite of [GreenTunnel](https://github.com/sadeghhayeri/greentunnel) in Rust.

Fracture is an anti-censorship utility designed to bypass Deep Packet Inspection (DPI) systems used by ISPs to block certain websites. By fragmenting TLS records and manipulating network traffic, it allows you to browse the internet freely and securely.

## Why This Rewrite?

The original GreenTunnel is fantastic, but relies on Node.js and Electron—both heavy on system resources. Fracture was built from scratch in Rust to deliver:

- **Zero Dependencies:** Ships as a single, self-contained binary. No Node.js or Electron required.
- **Lightweight & Fast:** Native desktop UI powered by [Dioxus](https://dioxuslabs.com/) with minimal memory footprint.
- **Better Performance:** Significantly faster network stream handling with memory safety guaranteed by Rust.
- **Powerful CLI:** Terminal-first experience with [Clap](https://github.com/clap-rs/clap) for flexible automation.
- **Dual Mode:** Use the GUI for ease or the CLI for headless/server deployments.

---

## Features

- **DPI Bypass:** Fragments TLS records and evades SNI inspection to bypass Deep Packet Inspection.
- **Modern GUI:** Clean, native desktop interface for configuration and one-click activation.
- **Powerful CLI:** Full terminal support for headless servers and automation.
- **Ultra-Lightweight:** Blazingly fast with minimal CPU and RAM usage.
- **System Proxy Integration:** Auto-configures OS proxy settings on activation (and reverts on exit).
- **Advanced DNS:** Built-in support for DNS-over-HTTPS with multiple providers.
- **Memory-Safe:** Written in Rust with zero runtime errors.

---

## Installation

### Pre-built Binaries

Download the latest binaries for Windows, macOS, and Linux from [Releases](https://github.com/Yoganand20/fracture/releases).

### Build from Source

Ensure [Rust is installed](https://rustup.rs/).

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Yoganand20/fracture.git
   cd fracture
   ```

2. **Build the project:**

   ```bash
   cargo build --release
   ```

   The compiled binary will be in `target/release/`.

---

## Usage

### GUI Mode (Desktop)

Launch the application to open the native Dioxus UI:

```bash
./fracture
```

The interface lets you:

- Configure DNS settings (provider, type, caching)
- Toggle TLS fragmentation and adjust fragment size
- Enable/disable HTTPS-only mode
- Start/stop the proxy with one click
- Monitor proxy status and connection information

### CLI Mode (Headless)

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

---

## Configuration

### Proxy Settings

- **Port:** Local listening port (default: 8081)
- **TLS Fragmentation:** Split TLS records to evade DPI inspection
- **Fragment Size:** Customize packet size for optimal bypass

### DNS Configuration

- **Provider:** Cloudflare, Google, Quad9, or custom URLs
- **Protocol:** DNS-over-HTTPS, DNS-over-QUIC, or standard DNS
- **Caching:** Built-in DNS cache to reduce latency

### System Proxy

The GUI automatically manages system proxy settings:

- **Activation:** Sets `127.0.0.1:PORT` as system proxy
- **Deactivation:** Removes proxy settings on exit (Windows supported)

---

## Building

### Desktop Binary

```bash
cargo build --release
./target/release/fracture
```

### CLI Binary Only

```bash
cargo build --release --bin fracture
./target/release/fracture --help
```

### Development Build

```bash
cargo run -- --help
cargo run --bin fracture -- --port 9000 --fragment
```

---

## Requirements

- **Windows 10+** (system proxy support)
- **macOS 10.13+**
- **Linux** (systemd/X11 environments)

No additional dependencies—Rust handles everything!

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## License

[Add your license here, e.g., MIT, GPL-3.0, etc.]

---

## Acknowledgments

This project is inspired by the original [GreenTunnel](https://github.com/sadeghhayeri/greentunnel) by Sadegh Hayeri.

---

## ⚠️ Legal Notice

Fracture is designed for legitimate privacy and anti-censorship use in regions with unreasonable internet restrictions. Users are responsible for complying with local laws and regulations. Misuse for malicious purposes is prohibited.
