# Layer 7 Packet Analyzer

[![Crates.io](https://img.shields.io/crates/v/layer7_packet_analyzer.svg)](https://crates.io/crates/parse_layer7)
[![Documentation](https://docs.rs/layer7_packet_analyzer/badge.svg)](https://docs.rs/parse_layer7/latest/parse_layer7)

## Overview

`layer7_packet_analyzer` is a Rust crate for parsing and analyzing various Layer 7 (application layer) network protocols. It supports protocols such as DNS, TLS, DHCP, HTTP, Modbus, NTP, and Bitcoin.

## Features

- Parse and analyze Layer 7 network protocols.
- Supports multiple protocols: DNS, TLS, DHCP, HTTP, Modbus, NTP, and Bitcoin.
- Provides data structures and functions for easy packet analysis.

## Usage

Add `layer7_packet_analyzer` to your `Cargo.toml`:

```toml
[dependencies]
layer7_packet_analyzer = "0.1.0"
```

### Example

Here is a basic example of how to use this crate to parse Layer 7 packet information:

```rust
use layer7_packet_analyzer::parse_layer_7_infos;

let packet: &[u8] = &[/* raw packet data */];
match parse_layer_7_infos(packet) {
    Some(info) => println!("Parsed Layer 7 Info: {}", info),
    None => println!("Unable to parse the packet."),
}
```

### Parsing Specific Protocols

You can also parse specific protocols directly using the respective modules. Here's an example for parsing a TLS packet:

```rust
use layer7_packet_analyzer::packet::tls::{parse_tls_packet, TlsPacket};

let tls_packet_data: &[u8] = &[/* raw TLS packet data */];
match parse_tls_packet(tls_packet_data) {
    Ok(tls_packet) => println!("Parsed TLS Packet: {:?}", tls_packet),
    Err(e) => println!("Failed to parse TLS packet: {}", e),
}
```

## Modules

### `packet`

The `packet` module contains submodules for each supported protocol. Each submodule provides the necessary functions to parse the protocol's packets and the data structures representing the parsed data.

### Example Modules

- `dns`: Functions and structures for parsing DNS packets.
- `tls`: Functions and structures for parsing TLS packets.
- `dhcp`: Functions and structures for parsing DHCP packets.
- `http`: Functions and structures for parsing HTTP requests.
- `modbus`: Functions and structures for parsing Modbus packets.
- `ntp`: Functions and structures for parsing NTP packets.
- `bitcoin`: Functions and structures for parsing Bitcoin packets.

## Structs and Enums

### `Layer7Info`

Represents the possible layer 7 information that can be parsed.

```rust
use layer7_packet_analyzer::packet::{
   bitcoin::{parse_bitcoin_packet, BitcoinPacket},
   dhcp::{parse_dhcp_packet, DhcpPacket},
   dns::{parse_dns_packet, DnsPacket},
   http::{parse_http_request, HttpRequest},
   modbus::{parse_modbus_packet, ModbusPacket},
   ntp::{parse_ntp_packet, NtpPacket},
   tls::{parse_tls_packet, TlsPacket},
};

#[derive(Debug)]
pub enum Layer7Info {
    DnsPacket(DnsPacket),
    TlsPacket(TlsPacket),
    DhcpPacket(DhcpPacket),
    HttpRequest(HttpRequest),
    ModbusPacket(ModbusPacket),
    NtpPacket(NtpPacket),
    BitcoinPacket(BitcoinPacket),
    None,
}
```

### `Layer7Infos`

Contains information about the layer 7 protocol and its parsed data.

## Examples

### Parse a TLS Packet

```rust
use layer7_packet_analyzer::parse_layer_7_infos;

let tls_payload = vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5]; // Example TLS payload
let result = parse_layer_7_infos(&tls_payload);

match result {
    Some(layer_7_infos) => println!("Parsed Info: {}", layer_7_infos),
    None => println!("Failed to parse the packet."),
}
```

### Parse a DNS Packet

```rust
use layer7_packet_analyzer::parse_layer_7_infos;

let dns_payload = vec![
    0xdd, 0xc7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
]; // Example DNS payload
let result = parse_layer_7_infos(&dns_payload);

match result {
    Some(layer_7_infos) => println!("Parsed Info: {}", layer_7_infos),
    None => println!("Failed to parse the packet."),
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.