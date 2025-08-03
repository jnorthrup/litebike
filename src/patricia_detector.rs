// Patricia Trie based protocol detector
// Optimized for fast, early-stage protocol identification

use std::collections::HashMap;
use log::{debug, trace};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Socks5,
    Tls,
    ProxyProtocol,
    Http2,
    WebSocket,
    Unknown,
}

/// Node in the Patricia Trie
struct PatriciaNode {
    children: HashMap<u8, PatriciaNode>,
    protocol: Option<Protocol>,
    // Store the length of the prefix that leads to this node
    prefix_len: usize,
}

impl PatriciaNode {
    fn new(prefix_len: usize) -> Self {
        PatriciaNode {
            children: HashMap::new(),
            protocol: None,
            prefix_len,
        }
    }
}

/// Patricia Trie for efficient protocol detection
pub struct PatriciaDetector {
    root: PatriciaNode,
}

impl PatriciaDetector {
    pub fn new() -> Self {
        let mut detector = PatriciaDetector {
            root: PatriciaNode::new(0),
        };
        detector.add_default_protocols();
        detector
    }

    /// Add a protocol pattern to the trie
    fn add_pattern(&mut self, pattern: &[u8], protocol: Protocol) {
        let mut current_node = &mut self.root;
        for (i, &byte) in pattern.iter().enumerate() {
            let prefix_len = i + 1;
            current_node = current_node.children.entry(byte)
                .or_insert_with(|| PatriciaNode::new(prefix_len));
        }
        current_node.protocol = Some(protocol);
    }

    /// Add common protocol patterns
    fn add_default_protocols(&mut self) {
        // HTTP methods
        self.add_pattern(b"GET ", Protocol::Http);
        self.add_pattern(b"POST ", Protocol::Http);
        self.add_pattern(b"PUT ", Protocol::Http);
        self.add_pattern(b"DELETE ", Protocol::Http);
        self.add_pattern(b"HEAD ", Protocol::Http);
        self.add_pattern(b"OPTIONS ", Protocol::Http);
        self.add_pattern(b"CONNECT ", Protocol::Http);
        self.add_pattern(b"PATCH ", Protocol::Http);

        // SOCKS5 handshake (version 5, 1 or more methods)
        self.add_pattern(&[0x05, 0x01], Protocol::Socks5); // SOCKS5, 1 method
        self.add_pattern(&[0x05, 0x02], Protocol::Socks5); // SOCKS5, 2 methods
        self.add_pattern(&[0x05, 0x03], Protocol::Socks5); // SOCKS5, 3 methods
        self.add_pattern(&[0x05, 0x04], Protocol::Socks5); // SOCKS5, 4 methods
        self.add_pattern(&[0x05, 0x05], Protocol::Socks5); // SOCKS5, 5 methods
        self.add_pattern(&[0x05, 0x06], Protocol::Socks5); // SOCKS5, 6 methods
        self.add_pattern(&[0x05, 0x07], Protocol::Socks5); // SOCKS5, 7 methods
        self.add_pattern(&[0x05, 0x08], Protocol::Socks5); // SOCKS5, 8 methods
        self.add_pattern(&[0x05, 0x09], Protocol::Socks5); // SOCKS5, 9 methods
        self.add_pattern(&[0x05, 0x0A], Protocol::Socks5); // SOCKS5, 10 methods

        // TLS Client Hello (Content Type: Handshake (0x16), Version: TLS 1.0-1.3 (0x0301-0x0304))
        self.add_pattern(&[0x16, 0x03, 0x01], Protocol::Tls); // TLS 1.0
        self.add_pattern(&[0x16, 0x03, 0x02], Protocol::Tls); // TLS 1.1
        self.add_pattern(&[0x16, 0x03, 0x03], Protocol::Tls); // TLS 1.2
        self.add_pattern(&[0x16, 0x03, 0x04], Protocol::Tls); // TLS 1.3

        // PROXY protocol (v1 and v2)
        self.add_pattern(b"PROXY ", Protocol::ProxyProtocol);
        self.add_pattern(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A], Protocol::ProxyProtocol); // PROXY v2 signature

        // HTTP/2 (Connection Preface)
        self.add_pattern(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Protocol::Http2);

        // WebSocket (Upgrade header - partial detection)
        self.add_pattern(b"GET / HTTP/1.1\r\nUpgrade: websocket", Protocol::WebSocket);
    }

    /// Detects the protocol from the given buffer.
    /// Returns the detected protocol.
    pub fn detect(&self, buffer: &[u8]) -> Protocol {
        let mut current_node = &self.root;
        let mut detected_protocol = Protocol::Unknown;
        let mut longest_match_len = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            if let Some(child_node) = current_node.children.get(&byte) {
                current_node = child_node;
                if let Some(protocol) = &current_node.protocol {
                    detected_protocol = protocol.clone();
                    longest_match_len = current_node.prefix_len;
                }
            } else {
                break;
            }
        }
        debug!("Detected {:?} with longest match length {}", detected_protocol, longest_match_len);
        detected_protocol
    }

    /// Detects the protocol and returns the detected protocol and the number of bytes consumed.
    pub fn detect_with_length(&self, buffer: &[u8]) -> (Protocol, usize) {
        let mut current_node = &self.root;
        let mut detected_protocol = Protocol::Unknown;
        let mut longest_match_len = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            if let Some(child_node) = current_node.children.get(&byte) {
                current_node = child_node;
                if let Some(protocol) = &current_node.protocol {
                    detected_protocol = protocol.clone();
                    longest_match_len = current_node.prefix_len;
                }
            } else {
                break;
            }
        }
        trace!("Detected {:?} with longest match length {}", detected_protocol, longest_match_len);
        (detected_protocol, longest_match_len)
    }
}

/// Convenience function for quick detection without creating a detector instance.
pub fn quick_detect(buffer: &[u8]) -> Option<Protocol> {
    let detector = PatriciaDetector::new();
    let (protocol, _) = detector.detect_with_length(buffer);
    if protocol == Protocol::Unknown {
        None
    } else {
        Some(protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(b"GET / HTTP/1.1"), Protocol::Http);
        assert_eq!(detector.detect(b"POST /api"), Protocol::Http);
        assert_eq!(detector.detect(b"CONNECT example.com:443"), Protocol::Http);
        assert_eq!(detector.detect(b"PUT /resource"), Protocol::Http);
    }

    #[test]
    fn test_socks5_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(&[0x05, 0x01, 0x00]), Protocol::Socks5);
        assert_eq!(detector.detect(&[0x05, 0x02, 0x00, 0x01]), Protocol::Socks5);
    }

    #[test]
    fn test_tls_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(&[0x16, 0x03, 0x03]), Protocol::Tls);
        assert_eq!(detector.detect(&[0x16, 0x03, 0x01]), Protocol::Tls);
    }

    #[test]
    fn test_proxy_protocol_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(b"PROXY TCP4 127.0.0.1 127.0.0.1 80 80\r\n"), Protocol::ProxyProtocol);
        assert_eq!(detector.detect(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]), Protocol::ProxyProtocol);
    }

    #[test]
    fn test_http2_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Protocol::Http2);
    }

    #[test]
    fn test_websocket_detection() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"), Protocol::WebSocket);
    }

    #[test]
    fn test_unknown_protocol() {
        let detector = PatriciaDetector::new();
        assert_eq!(detector.detect(b"RANDOM DATA"), Protocol::Unknown);
        assert_eq!(detector.detect(&[0x01, 0x02, 0x03]), Protocol::Unknown);
    }

    #[test]
    fn test_partial_match() {
        let detector = PatriciaDetector::new();
        // Partial HTTP match, should still be unknown until full prefix
        assert_eq!(detector.detect(b"GET"), Protocol::Unknown);
        assert_eq!(detector.detect(b"GET"), Protocol::Unknown);
    }

    #[test]
    fn test_detect_with_length() {
        let detector = PatriciaDetector::new();
        let (protocol, len) = detector.detect_with_length(b"GET / HTTP/1.1");
        assert_eq!(protocol, Protocol::Http);
        assert_eq!(len, 4);

        let (protocol, len) = detector.detect_with_length(&[0x05, 0x01, 0x00]);
        assert_eq!(protocol, Protocol::Socks5);
        assert_eq!(len, 2);

        let (protocol, len) = detector.detect_with_length(b"RANDOM DATA");
        assert_eq!(protocol, Protocol::Unknown);
        assert_eq!(len, 0);
    }
}