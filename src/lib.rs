//! # Layer 7 Packet Analyzer
//!
//! This crate provides functionality for parsing and analyzing various Layer 7 (application layer) network protocols. It supports protocols such as DNS, TLS, DHCP, HTTP, Modbus, NTP, and Bitcoin.
//!
//! ## Modules
//!
//! - `packet`: Contains submodules for each supported protocol, each providing parsing functions and data structures for the respective protocol.
//!
//! ## Usage
//!
//! The main function provided by this crate is `parse_layer_7_infos`, which attempts to detect and parse the protocol of a given TCP or UDP payload.
//!
//! ```rust
//! use parse_layer7::parse_layer_7_infos;
//!
//!     let packet: &[u8] = &[/* raw packet data */];
//!     match parse_layer_7_infos(packet) {
//!         Some(info) => println!("Parsed Layer 7 Info: {}", info),
//!         None => println!("Unable to parse the packet."),
//!     }
//! ```
//!
//! ## Modules Documentation
//!
//! ### `packet`
//!
//! The `packet` module contains submodules for each supported protocol. Each submodule provides the necessary functions to parse the protocol's packets and the data structures representing the parsed data.
//!
//! ### Example
//!
//! ```rust
//! use parse_layer7::packet::tls::{parse_tls_packet, TlsPacket};
//!
//!     let tls_packet_data: &[u8] = &[/* raw TLS packet data */];
//!     match parse_tls_packet(tls_packet_data) {
//!         Ok(tls_packet) => println!("Parsed TLS Packet: {:?}", tls_packet),
//!         Err(e) => println!("Failed to parse TLS packet: {}", e),
//!     }
//! ```
//!
//! ## Structs and Enums
//!
//! ### `Layer7Info`
//!
//! Represents the possible layer 7 information that can be parsed.
//!
//! ```rust
//! use parse_layer7::packet::{
//!    bitcoin::{parse_bitcoin_packet, BitcoinPacket},
//!    dhcp::{parse_dhcp_packet, DhcpPacket},
//!    http::{parse_http_request, HttpRequest},
//!    modbus::{parse_modbus_packet, ModbusPacket},
//!    ntp::{parse_ntp_packet, NtpPacket},
//!    tls::{parse_tls_packet, TlsPacket},
//! };
//!
//! #[derive(Debug)]
//! pub enum Layer7Info {
//!     TlsPacket(TlsPacket),
//!     DhcpPacket(DhcpPacket),
//!     HttpRequest(HttpRequest),
//!     ModbusPacket(ModbusPacket),
//!     NtpPacket(NtpPacket),
//!     BitcoinPacket(BitcoinPacket),
//!     None,
//! }
//! ```
//!
//! ### `Layer7Infos`
//!
//! Contains information about the layer 7 protocol and its parsed data.
//!
//!
//! # Examples
//!
//! ## Parse a TLS Packet
//!
//! ```rust
//! use parse_layer7::parse_layer_7_infos;
//!
//!     let tls_payload = vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5]; // Example TLS payload
//!     let result = parse_layer_7_infos(&tls_payload);
//!
//!     match result {
//!         Some(layer_7_infos) => println!("Parsed Info: {}", layer_7_infos),
//!         None => println!("Failed to parse the packet."),
//!     }
//! ```
//!
//! ## Parse a DNS Packet
//!
//! ```rust
//! use parse_layer7::parse_layer_7_infos;
//!
//!     let dns_payload = vec![
//!         0xdd, 0xc7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
//!         0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
//!     ]; // Example DNS payload
//!     let result = parse_layer_7_infos(&dns_payload);
//!
//!     match result {
//!         Some(layer_7_infos) => println!("Parsed Info: {}", layer_7_infos),
//!         None => println!("Failed to parse the packet."),
//!     }
//! ```
//!
//! ## Test Module
//!
//! The crate includes a `tests` module with tests for various packet types to ensure the correctness of the parsing functions.
//!
//! ```rust
//! #[cfg(test)]
//! mod tests {
//!     use super::*;
//!
//!     #[test]
//!     fn test_parse_layer_7_infos_tls() {
//!         // Test code for parsing TLS packets...
//!     }
//!
//!     #[test]
//!     fn test_parse_layer_7_infos_dns() {
//!         // Test code for parsing DNS packets...
//!     }
//!
//!     // Additional tests...
//! }
//! ```

pub mod packet;

use std::fmt::{self};

use crate::packet::{
    bitcoin::{parse_bitcoin_packet, BitcoinPacket},
    dhcp::{parse_dhcp_packet, DhcpPacket},
    http::{parse_http_request, HttpRequest},
    modbus::{parse_modbus_packet, ModbusPacket},
    ntp::{parse_ntp_packet, NtpPacket},
    tls::{parse_tls_packet, TlsPacket},
};

use detect_dns_packet::DnsPacket;

/// `Layer7Info` represents the possible layer 7 information that can be parsed.
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

impl fmt::Display for Layer7Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Layer7Info::DnsPacket(packet) => write!(f, "DNS Packet: {}", packet),
            Layer7Info::TlsPacket(packet) => write!(f, "TLS Packet: {}", packet),
            Layer7Info::DhcpPacket(packet) => write!(f, "DHCP Packet: {}", packet),
            Layer7Info::HttpRequest(packet) => write!(f, "HTTP Request: {}", packet),
            Layer7Info::ModbusPacket(packet) => write!(f, "MODBUS Packet: {}", packet),
            Layer7Info::NtpPacket(packet) => write!(f, "NTP packet {:?}", packet),
            Layer7Info::BitcoinPacket(packet) => write!(f, "Bitcoin Packet: {}", packet),
            Layer7Info::None => write!(f, "None"),
        }
    }
}

/// `Layer7Infos` contains information about the layer 7 protocol and its parsed data.
#[derive(Debug)]
pub struct Layer7Infos {
    pub layer_7_protocol: String,
    pub layer_7_protocol_infos: Option<Layer7Info>,
}

impl fmt::Display for Layer7Infos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Layer 7 Protocol: {}, Infos: {}",
            self.layer_7_protocol,
            self.layer_7_protocol_infos
                .as_ref()
                .map_or("None".to_string(), |infos| format!("{}", infos))
        )
    }
}

/// Tries to detect the protocol of the TCP or UDP payload given.
///
/// # Arguments
///
/// * `packet` - A byte slice representing the raw packet data.
///
/// # Returns
///
/// * `Option<Layer7Infos>` - Returns `Some(Layer7Infos)` if detection is successful, otherwise returns `None`.
pub fn parse_layer_7_infos(packet: &[u8]) -> Option<Layer7Infos> {
    if packet.is_empty() {
        return None;
    }

    // Attempt to parse as a TLS packet
    if let Ok(tls_packet) = parse_tls_packet(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "TLS".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::TlsPacket(tls_packet)),
        });
    }

    if let Ok(ntp_packet) = parse_ntp_packet(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "NTP".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::NtpPacket(ntp_packet)),
        });
    }

    // Attempt to parse as a DNS packet
    if let Ok(dns_packet) = DnsPacket::try_from(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "DNS".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::DnsPacket(dns_packet)),
        });
    }

    // Attempt to parse as a DHCP packet
    if let Ok(dhcp_packet) = parse_dhcp_packet(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "DHCP".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::DhcpPacket(dhcp_packet)),
        });
    }

    // Attempt to parse as an HTTP request
    if let Ok(http_request) = parse_http_request(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "HTTP".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::HttpRequest(http_request)),
        });
    }

    // Attempt to parse as a Modbus packet
    if let Ok(modbus_packet) = parse_modbus_packet(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "MODBUS".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::ModbusPacket(modbus_packet)),
        });
    }

    if let Ok(bitcoin_packet) = parse_bitcoin_packet(packet) {
        return Some(Layer7Infos {
            layer_7_protocol: "Bitcoin".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::BitcoinPacket(bitcoin_packet)),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tls::{TlsContentType, TlsVersion};

    #[test]
    fn test_parse_layer_7_infos_tls() {
        let tls_payload = vec![22, 3, 3, 0, 5, 1, 2, 3, 4, 5]; // Handshake, TLS 1.2, length 5
        let result = parse_layer_7_infos(&tls_payload);

        assert!(result.is_some());
        let layer_7_infos = result.unwrap();
        assert_eq!(layer_7_infos.layer_7_protocol, "TLS".to_string());
        if let Some(Layer7Info::TlsPacket(tls_packet)) = layer_7_infos.layer_7_protocol_infos {
            assert_eq!(tls_packet.content_type, TlsContentType::Handshake);
            assert_eq!(tls_packet.version, TlsVersion { major: 3, minor: 3 });
            assert_eq!(tls_packet.length, 5);
            assert_eq!(tls_packet.payload, vec![1, 2, 3, 4, 5]);
        } else {
            panic!("Expected Layer7Info::TlsPacket");
        }
    }

    #[test]
    fn test_parse_layer_7_infos_dns() {
        let dns_payload = vec![
            0xdd, 0xc7, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, // Answers
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Query
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // Null terminator of the domain name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        let result = parse_layer_7_infos(&dns_payload);

        assert!(result.is_some());
        let layer_7_infos = result.unwrap();
        assert_eq!(layer_7_infos.layer_7_protocol, "DNS".to_string());
        if let Some(Layer7Info::DnsPacket(dns_packet)) = layer_7_infos.layer_7_protocol_infos {
            assert_eq!(dns_packet.header.transaction_id, 0xddc7);
            assert_eq!(dns_packet.header.flags, 0x0100);
            assert_eq!(dns_packet.header.counts[0], 1);
            assert_eq!(dns_packet.header.counts[1], 0);
            assert_eq!(dns_packet.header.counts[2], 0);
            assert_eq!(dns_packet.header.counts[3], 0);
            assert_eq!(dns_packet.queries.queries.len(), 1);
            let query = &dns_packet.queries.queries[0];
            assert_eq!(query.name, "www.google.com");
            assert_eq!(query.qtype, detect_dns_packet::utils::dns_types::DnsType(1));
            assert_eq!(
                query.qclass,
                detect_dns_packet::utils::dns_class::DnsClass(1)
            );
        } else {
            panic!("Expected Layer7Info::DnsPacket");
        }
    }

    #[test]
    fn test_parse_dhcp_packet() {
        let dhcp_payload = [
            0x01, 0x01, 0x06, 0x00, // op, htype, hlen, hops
            0x39, 0x03, 0xF3, 0x26, // xid
            0x00, 0x00, // secs
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // ciaddr
            0x00, 0x00, 0x00, 0x00, // yiaddr
            0x00, 0x00, 0x00, 0x00, // siaddr
            0x00, 0x00, 0x00, 0x00, // giaddr
            0x00, 0x0C, 0x29, 0x36, 0x57, 0xD2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // chaddr
        ]
        .iter()
        .cloned()
        .chain([0x00; 64].iter().cloned())
        .chain([0x00; 128].iter().cloned())
        .chain(
            [
                0x63, 0x82, 0x53, 0x63, // Magic cookie
                0x35, 0x01, 0x05, // DHCP message type
                0xFF, // End option
            ]
            .iter()
            .cloned(),
        )
        .collect::<Vec<u8>>();

        let result = parse_layer_7_infos(&dhcp_payload);

        assert!(result.is_some());
        let layer_7_infos = result.unwrap();
        assert_eq!(layer_7_infos.layer_7_protocol, "DHCP".to_string());
        if let Some(Layer7Info::DhcpPacket(dhcp_packet)) = layer_7_infos.layer_7_protocol_infos {
            assert_eq!(dhcp_packet.op, 1);
            assert_eq!(dhcp_packet.htype, 1);
            assert_eq!(dhcp_packet.hlen, 6);
            assert_eq!(dhcp_packet.hops, 0);
            assert_eq!(dhcp_packet.xid, 0x3903F326);
            assert_eq!(dhcp_packet.secs, 0);
            assert_eq!(dhcp_packet.flags, 0);
            assert_eq!(dhcp_packet.ciaddr, [0, 0, 0, 0]);
            assert_eq!(dhcp_packet.yiaddr, [0, 0, 0, 0]);
            assert_eq!(dhcp_packet.siaddr, [0, 0, 0, 0]);
            assert_eq!(dhcp_packet.giaddr, [0, 0, 0, 0]);
            assert_eq!(
                dhcp_packet.chaddr,
                [
                    0x00, 0x0C, 0x29, 0x36, 0x57, 0xD2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00
                ]
            );
            assert_eq!(dhcp_packet.sname, [0u8; 64]);
            assert_eq!(dhcp_packet.file, [0u8; 128]);
            assert_eq!(
                dhcp_packet.options,
                vec![0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x05, 0xFF]
            );
        } else {
            panic!("Expected Layer7Info::DhcpPacket");
        }
    }

    #[test]
    fn test_parse_layer_7_infos_none() {
        let invalid_payload = vec![99, 3, 3, 0, 5, 1, 2, 3, 4, 5]; // Invalid packet
        let result = parse_layer_7_infos(&invalid_payload);

        assert!(result.is_none(), "Expected None for invalid packet");
    }

    #[test]
    fn test_layer7info_none() {
        let layer_7_info = Layer7Info::None;
        if let Layer7Info::None = layer_7_info {
            assert!(true);
        } else {
            assert!(false, "Expected Layer7Info::None");
        }
    }

    #[test]
    fn test_layer7infos_display() {
        let layer_7_infos = Layer7Infos {
            layer_7_protocol: "TLS".to_string(),
            layer_7_protocol_infos: Some(Layer7Info::None),
        };
        assert_eq!(
            format!("{}", layer_7_infos),
            "Layer 7 Protocol: TLS, Infos: None"
        );
    }

    #[test]
    fn test_layer7info_display() {
        let tls_packet = TlsPacket {
            content_type: TlsContentType::Handshake,
            version: TlsVersion { major: 3, minor: 3 },
            length: 5,
            payload: vec![1, 2, 3, 4, 5],
        };
        let layer_7_info = Layer7Info::TlsPacket(tls_packet);
        assert_eq!(
            format!("{}", layer_7_info),
            "TLS Packet: TLS Packet: content_type=Handshake, version=TLS 1.2, length=5, payload=[01, 02, 03, 04, 05]"
        );
    }
}
