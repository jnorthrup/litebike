// Fluent API Combinator DSL for Static Code Generation
// Generates extern "C" functions at compile time for zero-overhead protocol detection

use std::marker::PhantomData;

use crate::protocol_detector::{Protocol, DetectionResult};
use crate::fixed_range_constraints::{ConstrainedCombinator, ConstraintResult};

/// Marker traits for the type system to track combinator state
pub trait CombinatorState {}
pub struct Empty;
pub struct HasByte;
pub struct HasSequence;

impl CombinatorState for Empty {}
impl CombinatorState for HasByte {}
impl CombinatorState for HasSequence {}

/// Core combinator builder that generates static code blocks
#[derive(Debug, Clone)]
pub struct Combinator<S: CombinatorState> {
    pub pattern: Vec<PatternElement>,
    pub protocol: Protocol,
    pub confidence: u8,
    pub _state: PhantomData<S>,
}

/// Elements that can be part of a pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternElement {
    Byte(u8),
    Range(u8, u8),
    Any,
    Space,
    Bounded { min: usize, max: usize },
}

/// Static code generation metadata
#[derive(Debug, Clone)]
pub struct StaticCodeBlock {
    pub function_name: String,
    pub pattern: Vec<PatternElement>,
    pub protocol: Protocol,
    pub confidence: u8,
    pub byte_ranges: Vec<(u8, u8)>, // Start, end pairs for ownership table
}

impl Combinator<Empty> {
    /// Create a new combinator starting with a specific byte
    pub fn byte(value: u8) -> Combinator<HasByte> {
        Combinator {
            pattern: vec![PatternElement::Byte(value)],
            protocol: Protocol::Unknown,
            confidence: 255,
            _state: PhantomData,
        }
    }

    /// Create a new combinator starting with a byte range
    pub fn range(start: u8, end: u8) -> Combinator<HasByte> {
        Combinator {
            pattern: vec![PatternElement::Range(start, end)],
            protocol: Protocol::Unknown,
            confidence: 200,
            _state: PhantomData,
        }
    }

    /// Create a combinator that matches any byte
    pub fn any() -> Combinator<HasByte> {
        Combinator {
            pattern: vec![PatternElement::Any],
            protocol: Protocol::Unknown,
            confidence: 100,
            _state: PhantomData,
        }
    }

    /// Create a combinator that matches space (0x20)
    pub fn space() -> Combinator<HasByte> {
        Combinator {
            pattern: vec![PatternElement::Byte(0x20)],
            protocol: Protocol::Unknown,
            confidence: 180,
            _state: PhantomData,
        }
    }
}

impl<S: CombinatorState> Combinator<S> {
    /// Chain another combinator after this one
    pub fn then(mut self, next: PatternElement) -> Combinator<HasSequence> {
        self.pattern.push(next);
        Combinator {
            pattern: self.pattern,
            protocol: self.protocol,
            confidence: self.confidence,
            _state: PhantomData,
        }
    }

    /// Set the protocol this combinator detects
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the confidence level (0-255)
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    /// Add a bounded repetition (fixed width to prevent spec stalls)
    pub fn bounded(mut self, min: usize, max: usize) -> Self {
        self.pattern.push(PatternElement::Bounded { min, max });
        self
    }

    /// Generate static code block metadata
    pub fn build_static_block(self) -> StaticCodeBlock {
        let function_name = format!("check_{:?}", self.protocol).to_lowercase();
        let byte_ranges = self.compute_byte_ranges();
        
        StaticCodeBlock {
            function_name,
            pattern: self.pattern,
            protocol: self.protocol,
            confidence: self.confidence,
            byte_ranges,
        }
    }

    /// Compute byte ranges this combinator claims for the ownership table
    fn compute_byte_ranges(&self) -> Vec<(u8, u8)> {
        let mut ranges = Vec::new();
        
        for element in &self.pattern {
            match element {
                PatternElement::Byte(b) => ranges.push((*b, *b)),
                PatternElement::Range(start, end) => ranges.push((*start, *end)),
                PatternElement::Space => ranges.push((0x20, 0x20)),
                PatternElement::Any => {
                    // Any claims no specific bytes to avoid penalty
                }
                PatternElement::Bounded { .. } => {
                    // Bounded doesn't claim bytes directly
                }
            }
        }
        
        ranges
    }

    /// Generate the actual validator function
    pub fn generate_validator(&self) -> fn(&[u8], usize) -> Option<DetectionResult> {
        // For now, return a generic validator that will be replaced by macro generation
        match self.protocol {
            Protocol::Socks5 => validate_socks5_generated,
            Protocol::Http => validate_http_generated,
            Protocol::Tls => validate_tls_generated,
            _ => validate_unknown_generated,
        }
    }
}

/// Alternative combinator (OR logic)
impl<S: CombinatorState> Combinator<S> {
    pub fn or(self, other: Combinator<S>) -> AlternativeCombinator<S> {
        AlternativeCombinator {
            alternatives: vec![self, other],
            _state: PhantomData,
        }
    }
}

/// Combinator for handling alternatives (OR patterns)
#[derive(Debug, Clone)]
pub struct AlternativeCombinator<S: CombinatorState> {
    alternatives: Vec<Combinator<S>>,
    _state: PhantomData<S>,
}

impl<S: CombinatorState> AlternativeCombinator<S> {
    pub fn or(mut self, other: Combinator<S>) -> Self {
        self.alternatives.push(other);
        self
    }

    pub fn build_static_blocks(self) -> Vec<StaticCodeBlock> {
        self.alternatives
            .into_iter()
            .map(|c| c.build_static_block())
            .collect()
    }
}

/// Convenience functions for common patterns
pub mod patterns {
    use super::*;
    use crate::fixed_range_constraints::safe_patterns;

    /// SOCKS5 detection: byte 0x05 followed by any byte
    pub fn socks5() -> Combinator<HasSequence> {
        Combinator::byte(0x05)
            .then(PatternElement::Any)
            .protocol(Protocol::Socks5)
            .confidence(255)
    }

    /// HTTP GET method detection
    pub fn http_get() -> Combinator<HasSequence> {
        Combinator::byte(b'G')
            .then(PatternElement::Byte(b'E'))
            .then(PatternElement::Byte(b'T'))
            .then(PatternElement::Space)
            .protocol(Protocol::Http)
            .confidence(240)
    }

    /// HTTP POST method detection
    pub fn http_post() -> Combinator<HasSequence> {
        Combinator::byte(b'P')
            .then(PatternElement::Byte(b'O'))
            .then(PatternElement::Byte(b'S'))
            .then(PatternElement::Byte(b'T'))
            .then(PatternElement::Space)
            .protocol(Protocol::Http)
            .confidence(240)
    }

    /// HTTP CONNECT method detection
    pub fn http_connect() -> Combinator<HasSequence> {
        Combinator::byte(b'C')
            .then(PatternElement::Byte(b'O'))
            .then(PatternElement::Byte(b'N'))
            .then(PatternElement::Byte(b'N'))
            .then(PatternElement::Byte(b'E'))
            .then(PatternElement::Byte(b'C'))
            .then(PatternElement::Byte(b'T'))
            .then(PatternElement::Space)
            .protocol(Protocol::Connect)
            .confidence(250)
    }

    /// TLS handshake detection: 0x16 0x03 followed by version
    pub fn tls_handshake() -> Combinator<HasSequence> {
        Combinator::byte(0x16)
            .then(PatternElement::Byte(0x03))
            .then(PatternElement::Any) // Version byte
            .protocol(Protocol::Tls)
            .confidence(250)
    }

    /// HTTP/2 connection preface
    pub fn http2_preface() -> Combinator<HasSequence> {
        Combinator::byte(b'P')
            .then(PatternElement::Byte(b'R'))
            .then(PatternElement::Byte(b'I'))
            .then(PatternElement::Space)
            .protocol(Protocol::Http2)
            .confidence(255)
    }

    /// Safe pattern alternatives with built-in constraints
    pub mod safe {
        use super::*;

        /// Safe SOCKS5 pattern with guaranteed bounded execution
        pub fn socks5() -> Combinator<HasSequence> {
            safe_patterns::safe_socks5()
        }

        /// Safe HTTP GET pattern with guaranteed bounded execution
        pub fn http_get() -> Combinator<HasSequence> {
            safe_patterns::safe_http_get()
        }

        /// Safe TLS pattern with guaranteed bounded execution
        pub fn tls() -> Combinator<HasSequence> {
            safe_patterns::safe_tls()
        }

        /// Validate and convert any pattern to a safe constrained version
        pub fn make_safe<S: CombinatorState>(combinator: Combinator<S>) -> Result<Combinator<S>, ConstraintResult> {
            match combinator.validate_constraints() {
                ConstraintResult::Valid => Ok(combinator),
                error => {
                    // Try to create a constrained version
                    let constrained = combinator.with_constraints();
                    match constrained.validate_constraints() {
                        ConstraintResult::Valid => Ok(constrained),
                        _ => Err(error),
                    }
                }
            }
        }
    }
}

/// Generated validator functions (will be replaced by macro generation)
fn validate_socks5_generated(buffer: &[u8], pos: usize) -> Option<DetectionResult> {
    if buffer.len() >= pos + 2 && buffer[pos] == 0x05 {
        Some(DetectionResult::new(Protocol::Socks5, 255, 2))
    } else {
        None
    }
}

fn validate_http_generated(buffer: &[u8], pos: usize) -> Option<DetectionResult> {
    if buffer.len() < pos + 4 {
        return None;
    }
    
    let slice = &buffer[pos..];
    if slice.starts_with(b"GET ") || slice.starts_with(b"POST ") ||
       slice.starts_with(b"PUT ") || slice.starts_with(b"DELETE ") ||
       slice.starts_with(b"HEAD ") || slice.starts_with(b"OPTIONS ") ||
       slice.starts_with(b"TRACE ") {
        Some(DetectionResult::new(Protocol::Http, 240, 4))
    } else {
        None
    }
}

fn validate_tls_generated(buffer: &[u8], pos: usize) -> Option<DetectionResult> {
    if buffer.len() >= pos + 3 && buffer[pos] == 0x16 && buffer[pos+1] == 0x03 {
        Some(DetectionResult::new(Protocol::Tls, 250, 3))
    } else {
        None
    }
}

fn validate_unknown_generated(_buffer: &[u8], _pos: usize) -> Option<DetectionResult> {
    None
}

/// Macro for generating static extern "C" functions from combinators
/// This will be expanded to generate actual C-compatible functions
#[macro_export]
macro_rules! generate_static_detectors {
    ($($combinator:expr),* $(,)?) => {
        $(
            paste::paste! {
                #[no_mangle]
                pub extern "C" fn [<check_ $combinator.protocol:lower>](
                    buf: *const u8, 
                    len: usize
                ) -> u32 {
                    if buf.is_null() || len == 0 {
                        return 0;
                    }
                    
                    unsafe {
                        let slice = std::slice::from_raw_parts(buf, len);
                        match ($combinator.generate_validator())(slice, 0) {
                            Some(result) => result.confidence as u32,
                            None => 0,
                        }
                    }
                }
            }
        )*
    };
}

/// Static code block registry for compile-time generation
pub struct StaticCodeRegistry {
    pub blocks: Vec<StaticCodeBlock>,
}

impl StaticCodeRegistry {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
        }
    }

    pub fn register(&mut self, block: StaticCodeBlock) {
        self.blocks.push(block);
    }

    pub fn register_combinator<S: CombinatorState>(&mut self, combinator: Combinator<S>) {
        self.register(combinator.build_static_block());
    }

    pub fn generate_dispatch_table(&self) -> StaticDispatchTable {
        let dispatch = [null_detector as extern "C" fn(*const u8, usize) -> u32; 256];
        let mut penalties = [0u8; 256];
        
        // Build dispatch table and penalties from registered combinators
        for block in &self.blocks {
            for &(start, end) in &block.byte_ranges {
                for byte in start..=end {
                    penalties[byte as usize] += 1;
                    // For now, use the same function for all bytes
                    // In a full implementation, each pattern would have its own function
                }
            }
        }
        
        StaticDispatchTable {
            dispatch,
            penalties,
        }
    }
}

/// Static dispatch table generated at compile time
#[repr(C)]
pub struct StaticDispatchTable {
    pub dispatch: [extern "C" fn(*const u8, usize) -> u32; 256],
    pub penalties: [u8; 256],
}

extern "C" fn null_detector(_buf: *const u8, _len: usize) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::patterns::*;

    #[test]
    fn test_combinator_creation() {
        let socks5_combinator = socks5();
        let block = socks5_combinator.build_static_block();
        
        assert_eq!(block.protocol, Protocol::Socks5);
        assert_eq!(block.confidence, 255);
        assert_eq!(block.byte_ranges, vec![(0x05, 0x05)]);
    }

    #[test]
    fn test_http_combinator() {
        let get_combinator = http_get();
        let block = get_combinator.build_static_block();
        
        assert_eq!(block.protocol, Protocol::Http);
        assert_eq!(block.byte_ranges, vec![(b'G', b'G'), (b'E', b'E'), (b'T', b'T'), (0x20, 0x20)]);
    }

    #[test]
    fn test_alternative_combinator() {
        let http_methods = http_get()
            .or(http_post())
            .or(http_connect());
        
        let blocks = http_methods.build_static_blocks();
        assert_eq!(blocks.len(), 3);
        
        // All should be HTTP-related protocols
        for block in blocks {
            match block.protocol {
                Protocol::Http | Protocol::Connect => {},
                _ => panic!("Unexpected protocol: {:?}", block.protocol),
            }
        }
    }

    #[test]
    fn test_byte_range_computation() {
        let tls_combinator = tls_handshake();
        let block = tls_combinator.build_static_block();
        
        // Should claim bytes 0x16 and 0x03
        assert_eq!(block.byte_ranges, vec![(0x16, 0x16), (0x03, 0x03)]);
    }

    #[test]
    fn test_static_registry() {
        let mut registry = StaticCodeRegistry::new();
        
        registry.register_combinator(socks5());
        registry.register_combinator(http_get());
        registry.register_combinator(tls_handshake());
        
        let dispatch_table = registry.generate_dispatch_table();
        
        // Check penalties are computed correctly
        assert_eq!(dispatch_table.penalties[0x05], 1); // Only SOCKS5 claims 0x05
        assert_eq!(dispatch_table.penalties[b'G' as usize], 1); // Only HTTP GET claims 'G'
        assert_eq!(dispatch_table.penalties[0x16], 1); // Only TLS claims 0x16
    }
}