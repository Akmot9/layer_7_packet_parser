use std::fmt;

#[derive(Debug)]
pub struct DnsPacket {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority_rrs: u16,
    pub additional_rrs: u16,
    pub queries: Vec<DnsQuery>,
}

impl fmt::Display for DnsPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS Packet: transaction_id={:#X}, flags={:#X}, questions={}, answers={}, authority_rrs={}, additional_rrs={}, queries={:?}",
            self.transaction_id, self.flags, self.questions, self.answers, self.authority_rrs, self.additional_rrs, self.queries
        )
    }
}

#[derive(Debug)]
pub struct DnsQuery {
    pub name: String,
    pub query_type: u16,
    pub query_class: u16,
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS Query: name={}, query_type={}, query_class={}",
            self.name, self.query_type, self.query_class
        )
    }
}

/// Parses a DNS packet from a given payload.
///
/// # Arguments
///
/// * `payload` - A byte slice representing the raw DNS packet data.
///
/// # Returns
///
/// * `Result<DnsPacket, bool>` - Returns `Ok(DnsPacket)` if parsing is successful,
///   otherwise returns `Err(false)` indicating an invalid DNS packet.
pub fn parse_dns_packet(payload: &[u8]) -> Result<DnsPacket, bool> {
    if is_payload_too_short(payload, 12) {
        // println!("Payload too short for DNS packet: len = {}", payload.len());
        return Err(false);
    }

    let header = match parse_dns_header(payload) {
        Ok(header) => header,
        Err(e) => {
            println!("Error parsing DNS header: {}", e);
            return Err(false);
        }
    };

    let queries = match parse_dns_queries(payload, 12, header.questions) {
        Ok(queries) => queries,
        Err(e) => {
            println!("Error parsing DNS queries: {}", e);
            return Err(false);
        }
    };

    Ok(DnsPacket {
        transaction_id: header.transaction_id,
        flags: header.flags,
        questions: header.questions,
        answers: header.answers,
        authority_rrs: header.authority_rrs,
        additional_rrs: header.additional_rrs,
        queries,
    })
}

fn parse_dns_header(payload: &[u8]) -> Result<DnsHeader, &'static str> {
    if is_payload_too_short(payload, 12) {
        return Err("Payload too short to contain a DNS header");
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    let answers = u16::from_be_bytes([payload[6], payload[7]]);
    let authority_rrs = u16::from_be_bytes([payload[8], payload[9]]);
    let additional_rrs = u16::from_be_bytes([payload[10], payload[11]]);

    // println!("Parsed DNS header: transaction_id={:#X}, flags={:#X}, questions={}, answers={}, authority_rrs={}, additional_rrs={}",
    //     transaction_id, flags, questions, answers, authority_rrs, additional_rrs);

    if are_record_counts_unreasonable(questions, answers, authority_rrs, additional_rrs) {
        return Err("Unreasonable number of records");
    }

    Ok(DnsHeader {
        transaction_id,
        flags,
        questions,
        answers,
        authority_rrs,
        additional_rrs,
    })
}

fn parse_dns_queries(
    payload: &[u8],
    mut offset: usize,
    questions: u16,
) -> Result<Vec<DnsQuery>, &'static str> {
    let mut queries = Vec::new();

    for _i in 0..questions {
        // println!("Parsing query {}/{}", i + 1, questions);
        let (name, new_offset) = match parse_dns_name(payload, offset) {
            Ok(result) => result,
            Err(_) => {
                return Err("Failed to parse DNS name");
            }
        };
        offset = new_offset;
        if is_payload_too_short(payload, offset + 4) {
            return Err("Payload too short after parsing DNS name");
        }
        if name.is_empty() {
            return Err("DNS name is empty");
        }
        let query_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let query_class = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        offset += 4;
        // println!(
        //     "Parsed query: name={}, query_type={}, query_class={}",
        //     name, query_type, query_class
        // );
        queries.push(DnsQuery {
            name,
            query_type,
            query_class,
        });

        if queries.is_empty() {
            return Err("queries is empty");
        }
    }

    Ok(queries)
}

fn parse_dns_name(payload: &[u8], mut offset: usize) -> Result<(String, usize), bool> {
    let mut labels = Vec::new();
    while offset < payload.len() {
        let length = payload[offset] as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xC0 == 0xC0 {
            println!("Compression not supported at offset {}", offset);
            return Err(false); // Compression not supported in this example
        }
        offset += 1;
        if is_payload_too_short(payload, offset + length) {
            println!("Label length exceeds payload length at offset {}", offset);
            return Err(false);
        }
        labels.push(String::from_utf8_lossy(&payload[offset..offset + length]).to_string());
        offset += length;
    }
    let name = labels.join(".");
    //println!("Parsed DNS name: {}", name);
    Ok((name, offset))
}

fn is_payload_too_short(payload: &[u8], required_length: usize) -> bool {
    payload.len() < required_length
}

fn are_record_counts_unreasonable(
    questions: u16,
    answers: u16,
    authority_rrs: u16,
    additional_rrs: u16,
) -> bool {
    questions > 50 || answers > 50 || authority_rrs > 50 || additional_rrs > 50
}

#[derive(Debug)]
struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority_rrs: u16,
    additional_rrs: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_packet() {
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

        match parse_dns_packet(&dns_payload) {
            Ok(packet) => {
                assert_eq!(packet.transaction_id, 0xddc7);
                assert_eq!(packet.flags, 0x0100);
                assert_eq!(packet.questions, 1);
                assert_eq!(packet.answers, 0);
                assert_eq!(packet.authority_rrs, 0);
                assert_eq!(packet.additional_rrs, 0);
                assert_eq!(packet.queries.len(), 1);
                let query = &packet.queries[0];
                assert_eq!(query.name, "www.google.com");
                assert_eq!(query.query_type, 1);
                assert_eq!(query.query_class, 1);
            }
            Err(_) => panic!("Expected DNS packet"),
        }
    }

    #[test]
    fn test_parse_dns_packet_short_payload() {
        let short_payload = vec![0xdd, 0xc7, 0x01, 0x00, 0x00, 0x01, 0x00];
        match parse_dns_packet(&short_payload) {
            Ok(_) => panic!("Expected invalid DNS packet due to short payload"),
            Err(is_dns) => assert!(!is_dns),
        }
    }

    #[test]
    fn test_parse_dns_name() {
        let dns_payload = vec![
            0x03, 0x77, 0x77, 0x77, // "www"
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // Null terminator
        ];
        let (name, offset) = parse_dns_name(&dns_payload, 0).unwrap();
        assert_eq!(name, "www.google.com");
        assert_eq!(offset, dns_payload.len());
    }

    #[test]
    fn test_parse_dns_name_invalid() {
        // Invalid because it indicates a length that exceeds the payload length
        let dns_payload = vec![0x10, 0x77, 0x77, 0x77];
        assert!(parse_dns_name(&dns_payload, 0).is_err());
    }

    // #[test]
    // fn test_dns_does_not_parse_ntp_packet() {
    //     // This is an example NTP packet
    //     let ntp_payload = vec![
    //         0x1B, 0x00, 0x04, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x49,
    //         0x4E, 0x00, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00,
    //         0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0, 0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71, 0xDC, 0xC0,
    //         0x00, 0x00, 0xE1, 0x44, 0xC6, 0x71,
    //     ];

    //     match parse_dns_packet(&ntp_payload) {
    //         Ok(_) => assert!(false, "Expected non-DNS packet due to NTP payload"),
    //         Err(is_dns) => assert!(!is_dns),
    //     }
    // }
}
