// Static Code Generation Module
// Generates extern "C" functions and dispatch tables at compile time

use std::collections::HashMap;
use crate::combinator_dsl::{StaticCodeBlock, PatternElement, StaticCodeRegistry};
use crate::protocol_detector::{Protocol, DetectionResult};

/// Compile-time static code generator
pub struct StaticCodeGenerator {
    registry: StaticCodeRegistry,
    function_map: HashMap<u8, String>,
}

impl StaticCodeGenerator {
    pub fn new() -> Self {
        Self {
            registry: StaticCodeRegistry::new(),
            function_map: HashMap::new(),
        }
    }

    /// Register all built-in protocol combinators
    pub fn register_builtin_protocols(&mut self) {
        use crate::combinator_dsl::patterns::*;
        
        self.registry.register_combinator(socks5());
        self.registry.register_combinator(http_get());
        self.registry.register_combinator(http_post());
        self.registry.register_combinator(http_connect());
        self.registry.register_combinator(tls_handshake());
        self.registry.register_combinator(http2_preface());
        
        // Build function mapping for fast lookup
        self.build_function_map();
    }

    /// Build byte-to-function mapping
    fn build_function_map(&mut self) {
        for block in &self.registry.blocks {
            for &(start, end) in &block.byte_ranges {
                for byte in start..=end {
                    self.function_map.entry(byte)
                        .or_insert_with(|| block.function_name.clone());
                }
            }
        }
    }

    /// Generate the static dispatch table
    pub fn generate_dispatch_table(&self) -> StaticProtocolDetector {
        let mut dispatch = [null_detector as DetectorFn; 256];
        let mut penalties = [0u8; 256];
        
        // Assign detector functions based on byte ownership
        for (byte, function_name) in &self.function_map {
            dispatch[*byte as usize] = match function_name.as_str() {
                "check_socks5" => check_socks5_static,
                "check_http" => check_http_static,
                "check_connect" => check_connect_static,
                "check_tls" => check_tls_static,
                "check_http2" => check_http2_static,
                _ => null_detector,
            };
        }
        
        // Compute penalties (overlap counts)
        for block in &self.registry.blocks {
            for &(start, end) in &block.byte_ranges {
                for byte in start..=end {
                    penalties[byte as usize] += 1;
                }
            }
        }
        
        StaticProtocolDetector {
            dispatch,
            penalties,
        }
    }
}

/// Function pointer type for protocol detectors
pub type DetectorFn = extern "C" fn(*const u8, usize) -> u32;

/// Static protocol detector with compile-time generated dispatch table
#[repr(C)]
pub struct StaticProtocolDetector {
    dispatch: [DetectorFn; 256],
    penalties: [u8; 256],
}

impl StaticProtocolDetector {
    /// Detect protocol using static dispatch table
    #[inline(always)]
    pub fn detect(&self, buffer: &[u8]) -> DetectionResult {
        if buffer.is_empty() {
            return DetectionResult::unknown();
        }
        
        let first_byte = buffer[0];
        let detector_fn = self.dispatch[first_byte as usize];
        
        unsafe {
            let confidence = detector_fn(buffer.as_ptr(), buffer.len());
            match confidence {
                0 => DetectionResult::unknown(),
                255 => DetectionResult::new(Protocol::Socks5, 255, 2),
                250 => DetectionResult::new(Protocol::Tls, 250, 3),
                240 => DetectionResult::new(Protocol::Http, 240, 4),
                200 => DetectionResult::new(Protocol::Connect, 200, 8),
                _ => DetectionResult::new(Protocol::Unknown, confidence as u8, 1),
            }
        }
    }
    
    /// Get penalty (overlap count) for a byte
    pub fn penalty(&self, byte: u8) -> u8 {
        self.penalties[byte as usize]
    }
    
    /// Get the detector function for a byte
    pub fn get_detector(&self, byte: u8) -> DetectorFn {
        self.dispatch[byte as usize]
    }
}

// Static extern "C" detector functions - these are the generated code blocks

/// SOCKS5 detector: byte 0x05 followed by any byte
#[no_mangle]
pub extern "C" fn check_socks5_static(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len < 2 {
        return 0;
    }
    
    unsafe {
        if *buf == 0x05 {
            255 // High confidence SOCKS5
        } else {
            0
        }
    }
}

/// HTTP detector: check for common HTTP methods
#[no_mangle]
pub extern "C" fn check_http_static(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len < 4 {
        return 0;
    }
    
    unsafe {
        let slice = std::slice::from_raw_parts(buf, std::cmp::min(len, 8));
        
        if slice.starts_with(b"GET ") || 
           slice.starts_with(b"POST ") ||
           slice.starts_with(b"PUT ") ||
           slice.starts_with(b"DELETE ") ||
           slice.starts_with(b"HEAD ") ||
           slice.starts_with(b"OPTIONS ") ||
           slice.starts_with(b"TRACE ") {
            240 // High confidence HTTP
        } else {
            0
        }
    }
}

/// HTTP CONNECT detector
#[no_mangle]
pub extern "C" fn check_connect_static(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len < 8 {
        return 0;
    }
    
    unsafe {
        let slice = std::slice::from_raw_parts(buf, std::cmp::min(len, 8));
        
        if slice.starts_with(b"CONNECT ") {
            200 // Medium-high confidence CONNECT
        } else {
            0
        }
    }
}

/// TLS detector: 0x16 0x03 pattern
#[no_mangle]
pub extern "C" fn check_tls_static(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len < 3 {
        return 0;
    }
    
    unsafe {
        if *buf == 0x16 && *buf.offset(1) == 0x03 {
            250 // High confidence TLS
        } else {
            0
        }
    }
}

/// HTTP/2 detector: "PRI * HTTP/2.0" connection preface
#[no_mangle]
pub extern "C" fn check_http2_static(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len < 24 {
        return 0;
    }
    
    unsafe {
        let slice = std::slice::from_raw_parts(buf, std::cmp::min(len, 24));
        
        if slice.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            255 // Maximum confidence HTTP/2
        } else {
            0
        }
    }
}

/// Null detector for unclaimed bytes
#[no_mangle]
pub extern "C" fn null_detector(_buf: *const u8, _len: usize) -> u32 {
    0
}

/// Global static detector instance (initialized at compile time)
static mut GLOBAL_DETECTOR: Option<StaticProtocolDetector> = None;
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

/// Initialize the global static detector
pub fn init_static_detector() -> &'static StaticProtocolDetector {
    unsafe {
        INIT_ONCE.call_once(|| {
            let mut generator = StaticCodeGenerator::new();
            generator.register_builtin_protocols();
            GLOBAL_DETECTOR = Some(generator.generate_dispatch_table());
        });
        
        GLOBAL_DETECTOR.as_ref().unwrap()
    }
}

/// Get the global static detector instance
pub fn get_static_detector() -> &'static StaticProtocolDetector {
    unsafe {
        GLOBAL_DETECTOR.as_ref().unwrap_or_else(|| {
            init_static_detector()
        })
    }
}

/// Autovec optimization hints for the compiler
#[inline(always)]
pub fn detect_with_autovec(buffer: &[u8]) -> DetectionResult {
    let detector = get_static_detector();
    
    // Hint to compiler for auto-vectorization
    if buffer.len() >= 4 {
        // Check first 4 bytes in parallel when possible
        let chunk = &buffer[..4];
        for &byte in chunk {
            let penalty = detector.penalty(byte);
            if penalty == 1 {
                // This byte is only claimed by one protocol - high priority
                return detector.detect(&[byte]);
            }
        }
    }
    
    // Fallback to regular detection
    detector.detect(buffer)
}

/// Compile-time computation helpers
pub mod compile_time {
    use super::*;
    
    /// Generate jump table at compile time using const evaluation
    pub const fn generate_jump_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        
        // SOCKS5 claims 0x05
        table[0x05] = 1;
        
        // TLS claims 0x16
        table[0x16] = 2;
        
        // HTTP methods claim their first bytes
        table[b'G' as usize] = 3; // GET
        table[b'P' as usize] = 4; // POST, PUT, PRI
        table[b'D' as usize] = 3; // DELETE
        table[b'H' as usize] = 3; // HEAD
        table[b'O' as usize] = 3; // OPTIONS
        table[b'C' as usize] = 5; // CONNECT
        table[b'T' as usize] = 3; // TRACE
        
        table
    }
    
    /// Compute penalty table at compile time
    pub const fn compute_penalties() -> [u8; 256] {
        let mut penalties = [0u8; 256];
        
        // Count overlaps
        penalties[0x05] = 1; // Only SOCKS5
        penalties[0x16] = 1; // Only TLS
        penalties[b'G' as usize] = 1; // Only GET
        penalties[b'P' as usize] = 3; // POST, PUT, PRI (HTTP/2)
        penalties[b'D' as usize] = 1; // Only DELETE
        penalties[b'H' as usize] = 1; // Only HEAD
        penalties[b'O' as usize] = 1; // Only OPTIONS
        penalties[b'C' as usize] = 1; // Only CONNECT
        penalties[b'T' as usize] = 1; // Only TRACE
        
        penalties
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_detector_initialization() {
        let detector = init_static_detector();
        
        // Test that penalties are computed correctly
        assert_eq!(detector.penalty(0x05), 1); // SOCKS5 only
        assert_eq!(detector.penalty(0x16), 1); // TLS only
        assert!(detector.penalty(b'P') >= 1); // HTTP POST/PUT/PRI
    }

    #[test]
    fn test_socks5_detection() {
        let detector = get_static_detector();
        let socks5_data = [0x05, 0x01];
        
        let result = detector.detect(&socks5_data);
        assert_eq!(result.protocol, Protocol::Socks5);
        assert_eq!(result.confidence, 255);
    }

    #[test]
    fn test_http_detection() {
        let detector = get_static_detector();
        let http_data = b"GET / HTTP/1.1\r\n";
        
        let result = detector.detect(http_data);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.confidence, 240);
    }

    #[test]
    fn test_tls_detection() {
        let detector = get_static_detector();
        let tls_data = [0x16, 0x03, 0x01];
        
        let result = detector.detect(&tls_data);
        assert_eq!(result.protocol, Protocol::Tls);
        assert_eq!(result.confidence, 250);
    }

    #[test]
    fn test_extern_c_functions() {
        let socks5_data = [0x05, 0x01];
        let confidence = unsafe {
            check_socks5_static(socks5_data.as_ptr(), socks5_data.len())
        };
        assert_eq!(confidence, 255);
        
        let http_data = b"GET /";
        let confidence = unsafe {
            check_http_static(http_data.as_ptr(), http_data.len())
        };
        assert_eq!(confidence, 240);
        
        let tls_data = [0x16, 0x03, 0x01];
        let confidence = unsafe {
            check_tls_static(tls_data.as_ptr(), tls_data.len())
        };
        assert_eq!(confidence, 250);
    }

    #[test]
    fn test_autovec_optimization() {
        let test_data = b"GET / HTTP/1.1\r\n";
        let result = detect_with_autovec(test_data);
        
        assert_eq!(result.protocol, Protocol::Http);
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_compile_time_tables() {
        use compile_time::*;
        
        let jump_table = generate_jump_table();
        assert_eq!(jump_table[0x05], 1); // SOCKS5
        assert_eq!(jump_table[0x16], 2); // TLS
        assert_eq!(jump_table[b'G' as usize], 3); // GET
        
        let penalties = compute_penalties();
        assert_eq!(penalties[0x05], 1);
        assert_eq!(penalties[0x16], 1);
        assert_eq!(penalties[b'P' as usize], 3); // Multiple claimants
    }
}