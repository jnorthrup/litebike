// iface_demo: demonstrate litebike agent_8888 protocol detection
// (Network interface listing via literbike::syscall_net is available in literbike)

use litebike::agent_8888::{detect_protocol, ProtocolDetection, HttpMethod};

fn main() {
    let samples: &[(&str, &[u8])] = &[
        ("HTTP GET",    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("HTTP CONNECT",b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
        ("SOCKS5",      b"\x05\x01\x00"),
        ("WebSocket",   b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"),
        ("PAC",         b"GET /proxy.pac HTTP/1.1\r\n\r\n"),
        ("WPAD",        b"GET /wpad.dat HTTP/1.1\r\n\r\n"),
        ("UPnP",        b"M-SEARCH * HTTP/1.1\r\n\r\n"),
        ("Unknown",     b"\xDE\xAD\xBE\xEF"),
    ];

    println!("litebike agent_8888 protocol detection demo");
    println!("{:<16} {}", "Sample", "Detected");
    println!("{}", "-".repeat(40));
    for (label, buf) in samples {
        let detection = detect_protocol(buf);
        println!("{:<16} {:?}", label, detection);
    }
}
