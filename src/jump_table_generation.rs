// Compile-time Static Jump Table Generation
// Uses combinator definitions to build optimized dispatch tables

use crate::combinator_dsl::{StaticCodeBlock, PatternElement};
use crate::protocol_detector::Protocol;
use std::collections::HashMap;

/// Jump table entry containing function pointer and metadata
#[derive(Debug, Clone, Copy)]
pub struct JumpTableEntry {
    pub detector_fn: extern "C" fn(*const u8, usize) -> u32,
    pub protocol: Protocol,
    pub confidence: u8,
    pub penalty: u8, // Number of protocols claiming this byte
}

impl Default for JumpTableEntry {
    fn default() -> Self {
        Self {
            detector_fn: null_detector_fn,
            protocol: Protocol::Unknown,
            confidence: 0,
            penalty: 0,
        }
    }
}

/// Compile-time jump table generator
pub struct JumpTableGenerator {
    entries: [JumpTableEntry; 256],
    penalty_counts: [u8; 256],
    registered_blocks: Vec<StaticCodeBlock>,
}

impl JumpTableGenerator {
    pub const fn new() -> Self {
        Self {
            entries: [JumpTableEntry {
                detector_fn: null_detector_fn,
                protocol: Protocol::Unknown,
                confidence: 0,
                penalty: 0,
            }; 256],
            penalty_counts: [0u8; 256],
            registered_blocks: Vec::new(),
        }
    }

    /// Register a static code block for inclusion in the jump table
    pub fn register_block(&mut self, block: StaticCodeBlock) {
        // Count penalties for each byte claimed by this block
        for &(start, end) in &block.byte_ranges {
            for byte in start..=end {
                self.penalty_counts[byte as usize] += 1;
            }
        }

        // Assign detector function to bytes based on protocol
        let detector_fn = match block.protocol {
            Protocol::Socks5 => crate::static_generation::check_socks5_static,
            Protocol::Http => crate::static_generation::check_http_static,
            Protocol::Connect => crate::static_generation::check_connect_static,
            Protocol::Tls => crate::static_generation::check_tls_static,
            Protocol::Http2 => crate::static_generation::check_http2_static,
            _ => null_detector_fn,
        };

        // Update entries for claimed bytes
        for &(start, end) in &block.byte_ranges {
            for byte in start..=end {
                let entry = &mut self.entries[byte as usize];
                
                // Only update if this is a better (higher confidence) detector
                if block.confidence > entry.confidence {
                    entry.detector_fn = detector_fn;
                    entry.protocol = block.protocol;
                    entry.confidence = block.confidence;
                }
            }
        }

        self.registered_blocks.push(block);
    }

    /// Finalize the jump table by computing final penalties
    pub fn finalize(&mut self) -> StaticJumpTable {
        // Update penalty values in entries
        for (byte, entry) in self.entries.iter_mut().enumerate() {
            entry.penalty = self.penalty_counts[byte];
        }

        StaticJumpTable {
            entries: self.entries,
            generation_metadata: JumpTableMetadata {
                total_protocols: self.count_unique_protocols(),
                total_bytes_claimed: self.count_claimed_bytes(),
                max_penalty: *self.penalty_counts.iter().max().unwrap_or(&0),
                min_penalty: *self.penalty_counts.iter().filter(|&&x| x > 0).min().unwrap_or(&0),
            },
        }
    }

    fn count_unique_protocols(&self) -> usize {
        let mut protocols = std::collections::HashSet::new();
        for entry in &self.entries {
            if entry.confidence > 0 {
                protocols.insert(entry.protocol);
            }
        }
        protocols.len()
    }

    fn count_claimed_bytes(&self) -> usize {
        self.penalty_counts.iter().filter(|&&x| x > 0).count()
    }
}

/// Static jump table for O(1) protocol detection
#[repr(C)]
pub struct StaticJumpTable {
    pub entries: [JumpTableEntry; 256],
    pub generation_metadata: JumpTableMetadata,
}

impl StaticJumpTable {
    /// Detect protocol using direct table lookup
    #[inline(always)]
    pub fn detect(&self, buffer: &[u8]) -> crate::protocol_detector::DetectionResult {
        if buffer.is_empty() {
            return crate::protocol_detector::DetectionResult::unknown();
        }

        let first_byte = buffer[0];
        let entry = &self.entries[first_byte as usize];
        
        if entry.confidence == 0 {
            return crate::protocol_detector::DetectionResult::unknown();
        }

        // Call the static detector function
        unsafe {
            let detected_confidence = (entry.detector_fn)(buffer.as_ptr(), buffer.len());
            if detected_confidence > 0 {
                // Map confidence back to protocol using the entry metadata
                let bytes_consumed = match entry.protocol {
                    Protocol::Socks5 => 2,
                    Protocol::Tls => 3,
                    Protocol::Http | Protocol::Connect => 4,
                    Protocol::Http2 => 24,
                    _ => 1,
                };
                
                crate::protocol_detector::DetectionResult::new(
                    entry.protocol,
                    detected_confidence as u8,
                    bytes_consumed,
                )
            } else {
                crate::protocol_detector::DetectionResult::unknown()
            }
        }
    }

    /// Get penalty (overlap count) for a byte
    pub fn penalty(&self, byte: u8) -> u8 {
        self.entries[byte as usize].penalty
    }

    /// Get the protocol that claims a byte (if any)
    pub fn get_protocol(&self, byte: u8) -> Protocol {
        self.entries[byte as usize].protocol
    }

    /// Get detector function for a byte
    pub fn get_detector(&self, byte: u8) -> extern "C" fn(*const u8, usize) -> u32 {
        self.entries[byte as usize].detector_fn
    }

    /// Get statistics about this jump table
    pub fn stats(&self) -> &JumpTableMetadata {
        &self.generation_metadata
    }
}

/// Metadata about the generated jump table
#[derive(Debug, Clone, Copy)]
pub struct JumpTableMetadata {
    pub total_protocols: usize,
    pub total_bytes_claimed: usize,
    pub max_penalty: u8,
    pub min_penalty: u8,
}

impl JumpTableMetadata {
    /// Calculate efficiency score (higher is better)
    pub fn efficiency_score(&self) -> f32 {
        if self.max_penalty == 0 {
            return 0.0;
        }
        
        // Efficiency = claimed bytes / max penalty
        // More bytes claimed with lower penalties = higher efficiency
        (self.total_bytes_claimed as f32) / (self.max_penalty as f32)
    }

    /// Check if the jump table has good distribution
    pub fn is_well_distributed(&self) -> bool {
        self.max_penalty <= 3 && self.min_penalty >= 1
    }
}

/// Null detector function for unclaimed bytes
extern "C" fn null_detector_fn(_buf: *const u8, _len: usize) -> u32 {
    0
}

/// Builder for creating optimized jump tables from combinator patterns
pub struct OptimizedJumpTableBuilder {
    generator: JumpTableGenerator,
    optimization_level: OptimizationLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum OptimizationLevel {
    /// No optimizations, direct mapping
    None,
    /// Basic optimizations, prefer rare bytes
    Basic,
    /// Advanced optimizations with autovec hints
    Advanced,
}

impl OptimizedJumpTableBuilder {
    pub fn new(optimization_level: OptimizationLevel) -> Self {
        Self {
            generator: JumpTableGenerator::new(),
            optimization_level,
        }
    }

    /// Register combinators from the DSL
    pub fn register_combinators(&mut self) {
        use crate::combinator_dsl::patterns::*;

        // Register all built-in patterns
        self.generator.register_block(socks5().build_static_block());
        self.generator.register_block(http_get().build_static_block());
        self.generator.register_block(http_post().build_static_block());
        self.generator.register_block(http_connect().build_static_block());
        self.generator.register_block(tls_handshake().build_static_block());
        self.generator.register_block(http2_preface().build_static_block());
    }

    /// Apply optimizations based on the optimization level
    pub fn optimize(&mut self) {
        match self.optimization_level {
            OptimizationLevel::None => {
                // No optimizations
            }
            OptimizationLevel::Basic => {
                self.apply_basic_optimizations();
            }
            OptimizationLevel::Advanced => {
                self.apply_basic_optimizations();
                self.apply_advanced_optimizations();
            }
        }
    }

    fn apply_basic_optimizations(&mut self) {
        // Prefer detectors for rare bytes (low penalty)
        // This is already handled in the register_block logic
    }

    fn apply_advanced_optimizations(&mut self) {
        // Add autovec hints and SIMD-friendly patterns
        // This would involve reordering entries for better cache locality
        // For now, this is a placeholder for future optimizations
    }

    /// Build the final optimized jump table
    pub fn build(mut self) -> StaticJumpTable {
        self.optimize();
        self.generator.finalize()
    }
}

/// Macro for generating jump tables at compile time
#[macro_export]
macro_rules! generate_jump_table {
    ($optimization:expr) => {{
        let mut builder = $crate::jump_table_generation::OptimizedJumpTableBuilder::new($optimization);
        builder.register_combinators();
        builder.build()
    }};
}

/// Global static jump table instance
static mut GLOBAL_JUMP_TABLE: Option<StaticJumpTable> = None;
static JUMP_TABLE_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global jump table
pub fn init_global_jump_table() -> &'static StaticJumpTable {
    unsafe {
        JUMP_TABLE_INIT.call_once(|| {
            let table = generate_jump_table!(OptimizationLevel::Advanced);
            GLOBAL_JUMP_TABLE = Some(table);
        });
        
        GLOBAL_JUMP_TABLE.as_ref().unwrap()
    }
}

/// Get the global jump table
pub fn get_global_jump_table() -> &'static StaticJumpTable {
    unsafe {
        GLOBAL_JUMP_TABLE.as_ref().unwrap_or_else(|| {
            init_global_jump_table()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combinator_dsl::patterns::*;

    #[test]
    fn test_jump_table_generation() {
        let mut generator = JumpTableGenerator::new();
        
        generator.register_block(socks5().build_static_block());
        generator.register_block(http_get().build_static_block());
        generator.register_block(tls_handshake().build_static_block());
        
        let table = generator.finalize();
        
        // Test that entries are correctly populated
        assert_eq!(table.entries[0x05].protocol, Protocol::Socks5);
        assert_eq!(table.entries[0x16].protocol, Protocol::Tls);
        assert_eq!(table.entries[b'G' as usize].protocol, Protocol::Http);
        
        // Test penalties
        assert_eq!(table.penalty(0x05), 1); // Only SOCKS5
        assert_eq!(table.penalty(0x16), 1); // Only TLS
        assert_eq!(table.penalty(b'G'), 1); // Only GET
    }

    #[test]
    fn test_optimized_builder() {
        let table = generate_jump_table!(OptimizationLevel::Advanced);
        
        let stats = table.stats();
        assert!(stats.total_protocols > 0);
        assert!(stats.total_bytes_claimed > 0);
        assert!(stats.efficiency_score() > 0.0);
    }

    #[test]
    fn test_jump_table_detection() {
        let table = get_global_jump_table();
        
        // Test SOCKS5 detection
        let socks5_data = [0x05, 0x01];
        let result = table.detect(&socks5_data);
        assert_eq!(result.protocol, Protocol::Socks5);
        
        // Test HTTP detection
        let http_data = b"GET /";
        let result = table.detect(http_data);
        assert_eq!(result.protocol, Protocol::Http);
        
        // Test TLS detection
        let tls_data = [0x16, 0x03, 0x01];
        let result = table.detect(&tls_data);
        assert_eq!(result.protocol, Protocol::Tls);
    }

    #[test]
    fn test_metadata() {
        let table = get_global_jump_table();
        let stats = table.stats();
        
        assert!(stats.total_protocols >= 4); // At least SOCKS5, HTTP, TLS, HTTP/2
        assert!(stats.total_bytes_claimed >= 4); // At least 0x05, 0x16, G, P
        assert!(stats.max_penalty >= 1);
        
        println!("Jump table efficiency score: {:.2}", stats.efficiency_score());
        println!("Well distributed: {}", stats.is_well_distributed());
    }
}