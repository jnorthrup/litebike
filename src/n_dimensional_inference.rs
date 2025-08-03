// N-Dimensional Byte Range Inference System
// Extends protocol detection across multiple dimensions for sophisticated pattern matching

use crate::combinator_dsl::{PatternElement, StaticCodeBlock};
use crate::protocol_detector::Protocol;
use std::collections::HashMap;

/// Dimensions for protocol detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionDimension {
    /// Dimension 1: Byte value (0-255)
    ByteValue,
    /// Dimension 2: Buffer position/offset
    BufferPosition,
    /// Dimension 3: Protocol rarity ranking (fewer claimants = higher priority)
    RarityRanking,
    /// Dimension 4: Temporal ordering (Nagle buffering effects)
    TemporalOrdering,
    /// Dimension 5: Context-dependent continuations
    ContextualContinuation,
    /// Dimension 6: Byte sequence patterns
    SequencePattern,
    /// Dimension 7: Statistical likelihood
    StatisticalLikelihood,
}

/// A point in N-dimensional detection space
#[derive(Debug, Clone)]
pub struct DetectionPoint {
    pub dimensions: HashMap<DetectionDimension, f32>,
    pub protocol: Protocol,
    pub confidence: f32,
}

impl DetectionPoint {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            dimensions: HashMap::new(),
            protocol,
            confidence: 0.0,
        }
    }

    /// Set a dimension value
    pub fn set_dimension(mut self, dimension: DetectionDimension, value: f32) -> Self {
        self.dimensions.insert(dimension, value);
        self
    }

    /// Get dimension value or default
    pub fn get_dimension(&self, dimension: DetectionDimension) -> f32 {
        self.dimensions.get(&dimension).copied().unwrap_or(0.0)
    }

    /// Calculate Euclidean distance to another point
    pub fn distance_to(&self, other: &DetectionPoint) -> f32 {
        let mut sum_squares = 0.0;
        
        // Collect all dimensions from both points
        let mut all_dims: std::collections::HashSet<DetectionDimension> = std::collections::HashSet::new();
        all_dims.extend(self.dimensions.keys());
        all_dims.extend(other.dimensions.keys());
        
        for dim in all_dims {
            let self_val = self.get_dimension(*dim);
            let other_val = other.get_dimension(*dim);
            sum_squares += (self_val - other_val).powi(2);
        }
        
        sum_squares.sqrt()
    }
}

/// N-dimensional inference engine
pub struct NDimensionalInference {
    /// Training points for each protocol
    training_points: HashMap<Protocol, Vec<DetectionPoint>>,
    /// Dimension weights for importance
    dimension_weights: HashMap<DetectionDimension, f32>,
    /// Current detection context
    context: DetectionContext,
}

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub buffer_history: Vec<Vec<u8>>,
    pub temporal_sequence: Vec<u64>, // Timestamps
    pub previous_detections: Vec<Protocol>,
    pub session_metadata: SessionMetadata,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub connection_count: u32,
    pub average_packet_size: f32,
    pub dominant_protocol: Option<Protocol>,
    pub entropy_score: f32,
}

impl NDimensionalInference {
    pub fn new() -> Self {
        let mut inference = Self {
            training_points: HashMap::new(),
            dimension_weights: HashMap::new(),
            context: DetectionContext {
                buffer_history: Vec::new(),
                temporal_sequence: Vec::new(),
                previous_detections: Vec::new(),
                session_metadata: SessionMetadata {
                    connection_count: 0,
                    average_packet_size: 0.0,
                    dominant_protocol: None,
                    entropy_score: 0.0,
                },
            },
        };

        inference.initialize_default_weights();
        inference.initialize_training_data();
        inference
    }

    /// Initialize default dimension weights
    fn initialize_default_weights(&mut self) {
        self.dimension_weights.insert(DetectionDimension::ByteValue, 1.0);
        self.dimension_weights.insert(DetectionDimension::BufferPosition, 0.8);
        self.dimension_weights.insert(DetectionDimension::RarityRanking, 1.2);
        self.dimension_weights.insert(DetectionDimension::TemporalOrdering, 0.6);
        self.dimension_weights.insert(DetectionDimension::ContextualContinuation, 0.9);
        self.dimension_weights.insert(DetectionDimension::SequencePattern, 1.1);
        self.dimension_weights.insert(DetectionDimension::StatisticalLikelihood, 0.7);
    }

    /// Initialize training data from combinator patterns
    fn initialize_training_data(&mut self) {
        use crate::combinator_dsl::patterns::*;

        // SOCKS5 training points
        let socks5_block = socks5().build_static_block();
        self.add_training_point_from_block(&socks5_block);

        // HTTP training points
        let http_get_block = http_get().build_static_block();
        self.add_training_point_from_block(&http_get_block);

        let http_post_block = http_post().build_static_block();
        self.add_training_point_from_block(&http_post_block);

        let http_connect_block = http_connect().build_static_block();
        self.add_training_point_from_block(&http_connect_block);

        // TLS training points
        let tls_block = tls_handshake().build_static_block();
        self.add_training_point_from_block(&tls_block);

        // HTTP/2 training points
        let http2_block = http2_preface().build_static_block();
        self.add_training_point_from_block(&http2_block);
    }

    /// Convert a static code block to training points
    fn add_training_point_from_block(&mut self, block: &StaticCodeBlock) {
        for &(start_byte, end_byte) in &block.byte_ranges {
            for byte in start_byte..=end_byte {
                let point = DetectionPoint::new(block.protocol)
                    .set_dimension(DetectionDimension::ByteValue, byte as f32)
                    .set_dimension(DetectionDimension::RarityRanking, self.calculate_rarity(byte))
                    .set_dimension(DetectionDimension::SequencePattern, self.calculate_sequence_score(&block.pattern))
                    .set_dimension(DetectionDimension::StatisticalLikelihood, block.confidence as f32 / 255.0);

                self.training_points
                    .entry(block.protocol)
                    .or_insert_with(Vec::new)
                    .push(point);
            }
        }
    }

    /// Calculate rarity score for a byte (higher = rarer)
    fn calculate_rarity(&self, byte: u8) -> f32 {
        // Common bytes get lower scores, rare bytes get higher scores
        match byte {
            // Very rare control bytes
            0x05 | 0x16 => 10.0,
            // ASCII letters - moderately common
            b'A'..=b'Z' | b'a'..=b'z' => 5.0,
            // Digits - common
            b'0'..=b'9' => 3.0,
            // Space and common punctuation - very common
            b' ' | b'\r' | b'\n' | b'\t' => 1.0,
            // Everything else - somewhat rare
            _ => 7.0,
        }
    }

    /// Calculate sequence pattern complexity score
    fn calculate_sequence_score(&self, pattern: &[PatternElement]) -> f32 {
        let mut score = 0.0;
        
        for element in pattern {
            score += match element {
                PatternElement::Byte(_) => 2.0,       // Specific bytes are valuable
                PatternElement::Range(_, _) => 1.5,   // Ranges are somewhat valuable
                PatternElement::Any => 0.5,           // Any byte is not very specific
                PatternElement::Space => 1.8,         // Space is specific but common
                PatternElement::Bounded { min, max } => {
                    // Bounded patterns get score based on specificity
                    let range_size = max - min + 1;
                    2.0 / (range_size as f32).log2().max(1.0)
                }
            };
        }
        
        score
    }

    /// Perform N-dimensional inference on a buffer
    pub fn infer_protocol(&mut self, buffer: &[u8]) -> NDimensionalResult {
        if buffer.is_empty() {
            return NDimensionalResult::unknown();
        }

        // Update context
        self.update_context(buffer);

        // Create detection point for current buffer
        let current_point = self.create_detection_point(buffer);

        // Find nearest neighbors in N-dimensional space
        let mut protocol_scores: HashMap<Protocol, f32> = HashMap::new();

        for (protocol, training_points) in &self.training_points {
            let mut total_score = 0.0;
            let mut count = 0;

            for training_point in training_points {
                let distance = current_point.distance_to(training_point);
                let similarity = 1.0 / (1.0 + distance); // Convert distance to similarity
                total_score += similarity * training_point.confidence;
                count += 1;
            }

            if count > 0 {
                protocol_scores.insert(*protocol, total_score / count as f32);
            }
        }

        // Find the best protocol
        let best_protocol = protocol_scores
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(protocol, score)| (*protocol, *score))
            .unwrap_or((Protocol::Unknown, 0.0));

        NDimensionalResult {
            protocol: best_protocol.0,
            confidence: (best_protocol.1 * 255.0) as u8,
            dimension_scores: self.calculate_dimension_contributions(&current_point),
            context_influence: self.calculate_context_influence(),
            bytes_consumed: self.estimate_bytes_consumed(best_protocol.0),
        }
    }

    /// Create detection point from buffer
    fn create_detection_point(&self, buffer: &[u8]) -> DetectionPoint {
        let first_byte = buffer[0];
        
        DetectionPoint::new(Protocol::Unknown)
            .set_dimension(DetectionDimension::ByteValue, first_byte as f32)
            .set_dimension(DetectionDimension::BufferPosition, 0.0) // First byte
            .set_dimension(DetectionDimension::RarityRanking, self.calculate_rarity(first_byte))
            .set_dimension(DetectionDimension::TemporalOrdering, self.calculate_temporal_score())
            .set_dimension(DetectionDimension::ContextualContinuation, self.calculate_context_score())
            .set_dimension(DetectionDimension::SequencePattern, self.calculate_buffer_sequence_score(buffer))
            .set_dimension(DetectionDimension::StatisticalLikelihood, self.calculate_statistical_likelihood(buffer))
    }

    fn calculate_temporal_score(&self) -> f32 {
        // Score based on timing patterns
        let recent_detections = self.context.previous_detections.len();
        if recent_detections > 0 {
            // Favor protocols that appeared recently
            1.0 + (recent_detections as f32 * 0.1)
        } else {
            1.0
        }
    }

    fn calculate_context_score(&self) -> f32 {
        // Score based on session context
        if let Some(_dominant) = self.context.session_metadata.dominant_protocol {
            // Favor the dominant protocol
            2.0
        } else {
            1.0
        }
    }

    fn calculate_buffer_sequence_score(&self, buffer: &[u8]) -> f32 {
        // Score based on byte sequence patterns
        let mut score = 0.0;
        
        for &byte in buffer.iter().take(8) { // Look at first 8 bytes
            if byte.is_ascii_alphabetic() {
                score += 1.0;
            } else if byte == 0x05 || byte == 0x16 {
                score += 3.0; // High value for protocol-specific bytes
            }
        }
        
        score / buffer.len().min(8) as f32
    }

    fn calculate_statistical_likelihood(&self, buffer: &[u8]) -> f32 {
        // Calculate entropy-based likelihood
        let mut byte_counts = [0u32; 256];
        for &byte in buffer {
            byte_counts[byte as usize] += 1;
        }
        
        let mut entropy = 0.0;
        let len = buffer.len() as f32;
        
        for count in byte_counts.iter() {
            if *count > 0 {
                let probability = *count as f32 / len;
                entropy -= probability * probability.log2();
            }
        }
        
        // Normalize entropy (max is 8.0 for uniform distribution)
        entropy / 8.0
    }

    fn update_context(&mut self, buffer: &[u8]) {
        // Update buffer history (keep last 10)
        self.context.buffer_history.push(buffer.to_vec());
        if self.context.buffer_history.len() > 10 {
            self.context.buffer_history.remove(0);
        }

        // Update temporal sequence
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.context.temporal_sequence.push(now);
        if self.context.temporal_sequence.len() > 10 {
            self.context.temporal_sequence.remove(0);
        }

        // Update session metadata
        self.context.session_metadata.connection_count += 1;
        self.context.session_metadata.average_packet_size = 
            (self.context.session_metadata.average_packet_size + buffer.len() as f32) / 2.0;
    }

    fn calculate_dimension_contributions(&self, point: &DetectionPoint) -> HashMap<DetectionDimension, f32> {
        let mut contributions = HashMap::new();
        
        for (dimension, value) in &point.dimensions {
            let weight = self.dimension_weights.get(dimension).copied().unwrap_or(1.0);
            contributions.insert(*dimension, value * weight);
        }
        
        contributions
    }

    fn calculate_context_influence(&self) -> f32 {
        // Calculate how much context influenced the decision
        let history_influence = self.context.buffer_history.len() as f32 * 0.1;
        let temporal_influence = self.context.temporal_sequence.len() as f32 * 0.05;
        
        (history_influence + temporal_influence).min(1.0)
    }

    fn estimate_bytes_consumed(&self, protocol: Protocol) -> usize {
        match protocol {
            Protocol::Socks5 => 2,
            Protocol::Tls => 3,
            Protocol::Http | Protocol::Connect => 4,
            Protocol::Http2 => 24,
            _ => 1,
        }
    }
}

/// Result of N-dimensional inference
#[derive(Debug, Clone)]
pub struct NDimensionalResult {
    pub protocol: Protocol,
    pub confidence: u8,
    pub dimension_scores: HashMap<DetectionDimension, f32>,
    pub context_influence: f32,
    pub bytes_consumed: usize,
}

impl NDimensionalResult {
    pub fn unknown() -> Self {
        Self {
            protocol: Protocol::Unknown,
            confidence: 0,
            dimension_scores: HashMap::new(),
            context_influence: 0.0,
            bytes_consumed: 0,
        }
    }

    /// Convert to standard DetectionResult
    pub fn to_detection_result(&self) -> crate::protocol_detector::DetectionResult {
        crate::protocol_detector::DetectionResult::new(
            self.protocol,
            self.confidence,
            self.bytes_consumed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_point_distance() {
        let point1 = DetectionPoint::new(Protocol::Socks5)
            .set_dimension(DetectionDimension::ByteValue, 5.0)
            .set_dimension(DetectionDimension::RarityRanking, 10.0);
            
        let point2 = DetectionPoint::new(Protocol::Http)
            .set_dimension(DetectionDimension::ByteValue, 3.0)
            .set_dimension(DetectionDimension::RarityRanking, 8.0);
            
        let distance = point1.distance_to(&point2);
        
        // Distance should be sqrt((5-3)^2 + (10-8)^2) = sqrt(4 + 4) = sqrt(8) ≈ 2.83
        assert!((distance - 2.83).abs() < 0.01);
    }

    #[test]
    fn test_n_dimensional_inference() {
        let mut inference = NDimensionalInference::new();
        
        // Test SOCKS5 detection
        let socks5_data = [0x05, 0x01];
        let result = inference.infer_protocol(&socks5_data);
        assert_eq!(result.protocol, Protocol::Socks5);
        assert!(result.confidence > 0);
        
        // Test HTTP detection
        let http_data = b"GET /";
        let result = inference.infer_protocol(http_data);
        assert_eq!(result.protocol, Protocol::Http);
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_rarity_calculation() {
        let inference = NDimensionalInference::new();
        
        // SOCKS5 version byte should be very rare
        assert!(inference.calculate_rarity(0x05) > inference.calculate_rarity(b' '));
        
        // TLS content type should be very rare
        assert!(inference.calculate_rarity(0x16) > inference.calculate_rarity(b'A'));
        
        // Space should be common (low rarity)
        assert!(inference.calculate_rarity(b' ') < inference.calculate_rarity(0x05));
    }

    #[test]
    fn test_context_updates() {
        let mut inference = NDimensionalInference::new();
        
        let initial_count = inference.context.session_metadata.connection_count;
        
        inference.infer_protocol(&[0x05, 0x01]);
        
        assert_eq!(
            inference.context.session_metadata.connection_count,
            initial_count + 1
        );
        assert_eq!(inference.context.buffer_history.len(), 1);
        assert_eq!(inference.context.temporal_sequence.len(), 1);
    }

    #[test]
    fn test_dimension_contributions() {
        let inference = NDimensionalInference::new();
        
        let point = DetectionPoint::new(Protocol::Socks5)
            .set_dimension(DetectionDimension::ByteValue, 5.0)
            .set_dimension(DetectionDimension::RarityRanking, 10.0);
            
        let contributions = inference.calculate_dimension_contributions(&point);
        
        assert!(contributions.contains_key(&DetectionDimension::ByteValue));
        assert!(contributions.contains_key(&DetectionDimension::RarityRanking));
        
        // Rarity ranking should have higher contribution due to higher weight
        let byte_contrib = contributions[&DetectionDimension::ByteValue];
        let rarity_contrib = contributions[&DetectionDimension::RarityRanking];
        assert!(rarity_contrib > byte_contrib);
    }
}