// Fixed Byte Range Constraints Module
// Prevents specification stalls by enforcing bounded pattern matching

use crate::combinator_dsl::{PatternElement, Combinator, CombinatorState};
use crate::protocol_detector::Protocol;
use std::collections::HashMap;

/// Maximum allowed pattern length to prevent spec stalls
pub const MAX_PATTERN_LENGTH: usize = 32;

/// Maximum allowed range size for byte ranges
pub const MAX_RANGE_SIZE: u8 = 64;

/// Maximum lookahead distance for pattern matching
pub const MAX_LOOKAHEAD: usize = 8;

/// Constraint validation result
#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintResult {
    Valid,
    TooLong { actual: usize, max: usize },
    RangeTooLarge { actual: u8, max: u8 },
    UnboundedPattern,
    ExcessiveLookahead { actual: usize, max: usize },
    InfiniteLoop,
}

/// Fixed range constraint enforcer
pub struct ConstraintEnforcer {
    max_pattern_length: usize,
    max_range_size: u8,
    max_lookahead: usize,
    pattern_cache: HashMap<Vec<PatternElement>, ConstraintResult>,
}

impl Default for ConstraintEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintEnforcer {
    pub fn new() -> Self {
        Self {
            max_pattern_length: MAX_PATTERN_LENGTH,
            max_range_size: MAX_RANGE_SIZE,
            max_lookahead: MAX_LOOKAHEAD,
            pattern_cache: HashMap::new(),
        }
    }

    /// Create enforcer with custom limits
    pub fn with_limits(max_pattern_length: usize, max_range_size: u8, max_lookahead: usize) -> Self {
        Self {
            max_pattern_length,
            max_range_size,
            max_lookahead,
            pattern_cache: HashMap::new(),
        }
    }

    /// Validate a pattern against fixed range constraints
    pub fn validate_pattern(&mut self, pattern: &[PatternElement]) -> ConstraintResult {
        // Check cache first
        if let Some(cached_result) = self.pattern_cache.get(pattern) {
            return cached_result.clone();
        }

        let result = self.validate_pattern_internal(pattern);
        self.pattern_cache.insert(pattern.to_vec(), result.clone());
        result
    }

    fn validate_pattern_internal(&self, pattern: &[PatternElement]) -> ConstraintResult {
        // Check total pattern length
        if pattern.len() > self.max_pattern_length {
            return ConstraintResult::TooLong {
                actual: pattern.len(),
                max: self.max_pattern_length,
            };
        }

        // Check individual elements
        for element in pattern {
            match self.validate_element(element) {
                ConstraintResult::Valid => continue,
                other => return other,
            }
        }

        // Check for potential infinite loops or unbounded patterns
        if self.has_unbounded_repetition(pattern) {
            return ConstraintResult::UnboundedPattern;
        }

        // Check lookahead requirements
        let lookahead = self.calculate_lookahead_requirement(pattern);
        if lookahead > self.max_lookahead {
            return ConstraintResult::ExcessiveLookahead {
                actual: lookahead,
                max: self.max_lookahead,
            };
        }

        ConstraintResult::Valid
    }

    fn validate_element(&self, element: &PatternElement) -> ConstraintResult {
        match element {
            PatternElement::Byte(_) => ConstraintResult::Valid,
            PatternElement::Range(start, end) => {
                let range_size = end.saturating_sub(*start).saturating_add(1);
                if range_size > self.max_range_size {
                    ConstraintResult::RangeTooLarge {
                        actual: range_size,
                        max: self.max_range_size,
                    }
                } else {
                    ConstraintResult::Valid
                }
            }
            PatternElement::Any => ConstraintResult::Valid,
            PatternElement::Space => ConstraintResult::Valid,
            PatternElement::Bounded { min, max } => {
                if *max == usize::MAX || (*max - min) > self.max_pattern_length {
                    ConstraintResult::UnboundedPattern
                } else {
                    ConstraintResult::Valid
                }
            }
        }
    }

    fn has_unbounded_repetition(&self, pattern: &[PatternElement]) -> bool {
        for element in pattern {
            if let PatternElement::Bounded { min: _, max } = element {
                if *max == usize::MAX {
                    return true;
                }
            }
        }
        false
    }

    fn calculate_lookahead_requirement(&self, pattern: &[PatternElement]) -> usize {
        let mut max_lookahead = 0;
        let mut current_position = 0;

        for element in pattern {
            match element {
                PatternElement::Byte(_) | PatternElement::Range(_, _) | 
                PatternElement::Any | PatternElement::Space => {
                    current_position += 1;
                }
                PatternElement::Bounded { min: _, max } => {
                    current_position += *max;
                }
            }
            max_lookahead = max_lookahead.max(current_position);
        }

        max_lookahead
    }

    /// Create a constrained version of a pattern that satisfies all limits
    pub fn constrain_pattern(&self, pattern: &[PatternElement]) -> Vec<PatternElement> {
        let mut constrained = Vec::new();
        let mut remaining_length = self.max_pattern_length;

        for element in pattern {
            if remaining_length == 0 {
                break;
            }

            let constrained_element = match element {
                PatternElement::Range(start, end) => {
                    let range_size = end.saturating_sub(*start).saturating_add(1);
                    if range_size > self.max_range_size {
                        // Split large range into smaller ranges
                        let new_end = start.saturating_add(self.max_range_size - 1);
                        PatternElement::Range(*start, new_end)
                    } else {
                        *element
                    }
                }
                PatternElement::Bounded { min, max } => {
                    let constrained_max = (*max).min(self.max_pattern_length);
                    PatternElement::Bounded {
                        min: *min,
                        max: constrained_max,
                    }
                }
                _ => *element,
            };

            constrained.push(constrained_element);
            remaining_length = remaining_length.saturating_sub(1);
        }

        constrained
    }
}

/// Extension trait for Combinators to add constraint checking
pub trait ConstrainedCombinator<S: CombinatorState> {
    /// Validate this combinator against fixed range constraints
    fn validate_constraints(&self) -> ConstraintResult;
    
    /// Create a constrained version that satisfies all limits
    fn with_constraints(self) -> Self;
    
    /// Check if this combinator is bounded (finite execution time)
    fn is_bounded(&self) -> bool;
}

impl<S: CombinatorState> ConstrainedCombinator<S> for Combinator<S> {
    fn validate_constraints(&self) -> ConstraintResult {
        let mut enforcer = ConstraintEnforcer::new();
        enforcer.validate_pattern(&self.pattern)
    }

    fn with_constraints(self) -> Self {
        let enforcer = ConstraintEnforcer::new();
        let constrained_pattern = enforcer.constrain_pattern(&self.pattern);
        
        Combinator {
            pattern: constrained_pattern,
            protocol: self.protocol,
            confidence: self.confidence,
            _state: self._state,
        }
    }

    fn is_bounded(&self) -> bool {
        for element in &self.pattern {
            if let PatternElement::Bounded { min: _, max } = element {
                if *max == usize::MAX {
                    return false;
                }
            }
        }
        true
    }
}

/// Bounded pattern builder for creating safe patterns
pub struct BoundedPatternBuilder {
    elements: Vec<PatternElement>,
    enforcer: ConstraintEnforcer,
}

impl BoundedPatternBuilder {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            enforcer: ConstraintEnforcer::new(),
        }
    }

    /// Add a bounded byte sequence
    pub fn byte_sequence(mut self, bytes: &[u8]) -> Result<Self, ConstraintResult> {
        for &byte in bytes {
            if self.elements.len() >= self.enforcer.max_pattern_length {
                return Err(ConstraintResult::TooLong {
                    actual: self.elements.len() + 1,
                    max: self.enforcer.max_pattern_length,
                });
            }
            self.elements.push(PatternElement::Byte(byte));
        }
        Ok(self)
    }

    /// Add a bounded range
    pub fn bounded_range(mut self, start: u8, end: u8) -> Result<Self, ConstraintResult> {
        let range_size = end.saturating_sub(start).saturating_add(1);
        if range_size > self.enforcer.max_range_size {
            return Err(ConstraintResult::RangeTooLarge {
                actual: range_size,
                max: self.enforcer.max_range_size,
            });
        }

        if self.elements.len() >= self.enforcer.max_pattern_length {
            return Err(ConstraintResult::TooLong {
                actual: self.elements.len() + 1,
                max: self.enforcer.max_pattern_length,
            });
        }

        self.elements.push(PatternElement::Range(start, end));
        Ok(self)
    }

    /// Add a strictly bounded repetition
    pub fn bounded_any(mut self, min: usize, max: usize) -> Result<Self, ConstraintResult> {
        if max > self.enforcer.max_lookahead {
            return Err(ConstraintResult::ExcessiveLookahead {
                actual: max,
                max: self.enforcer.max_lookahead,
            });
        }

        if max == usize::MAX {
            return Err(ConstraintResult::UnboundedPattern);
        }

        if self.elements.len() >= self.enforcer.max_pattern_length {
            return Err(ConstraintResult::TooLong {
                actual: self.elements.len() + 1,
                max: self.enforcer.max_pattern_length,
            });
        }

        self.elements.push(PatternElement::Bounded { min, max });
        Ok(self)
    }

    /// Build the final pattern with validation
    pub fn build(mut self, _protocol: Protocol) -> Result<Vec<PatternElement>, ConstraintResult> {
        match self.enforcer.validate_pattern(&self.elements) {
            ConstraintResult::Valid => Ok(self.elements),
            error => Err(error),
        }
    }
}

/// Safe pattern constructors that enforce constraints
pub mod safe_patterns {
    use super::*;
    use crate::combinator_dsl::Combinator;

    /// Create a bounded SOCKS5 pattern (guaranteed safe)
    pub fn safe_socks5() -> Combinator<crate::combinator_dsl::HasSequence> {
        BoundedPatternBuilder::new()
            .byte_sequence(&[0x05])
            .unwrap()
            .bounded_any(1, 1)
            .unwrap()
            .build(Protocol::Socks5)
            .map(|pattern| Combinator {
                pattern,
                protocol: Protocol::Socks5,
                confidence: 255,
                _state: std::marker::PhantomData,
            })
            .unwrap()
    }

    /// Create a bounded HTTP GET pattern (guaranteed safe)
    pub fn safe_http_get() -> Combinator<crate::combinator_dsl::HasSequence> {
        BoundedPatternBuilder::new()
            .byte_sequence(b"GET ")
            .unwrap()
            .build(Protocol::Http)
            .map(|pattern| Combinator {
                pattern,
                protocol: Protocol::Http,
                confidence: 240,
                _state: std::marker::PhantomData,
            })
            .unwrap()
    }

    /// Create a bounded TLS pattern (guaranteed safe)
    pub fn safe_tls() -> Combinator<crate::combinator_dsl::HasSequence> {
        BoundedPatternBuilder::new()
            .byte_sequence(&[0x16, 0x03])
            .unwrap()
            .bounded_any(1, 1)
            .unwrap()
            .build(Protocol::Tls)
            .map(|pattern| Combinator {
                pattern,
                protocol: Protocol::Tls,
                confidence: 250,
                _state: std::marker::PhantomData,
            })
            .unwrap()
    }
}

/// Execution time estimator for patterns
pub struct ExecutionTimeEstimator;

impl ExecutionTimeEstimator {
    /// Estimate worst-case execution time in CPU cycles
    pub fn estimate_cycles(pattern: &[PatternElement]) -> u64 {
        let mut total_cycles = 0;

        for element in pattern {
            total_cycles += match element {
                PatternElement::Byte(_) => 2,           // Simple comparison
                PatternElement::Range(_, _) => 4,       // Range check
                PatternElement::Any => 1,               // No check needed
                PatternElement::Space => 2,             // Simple comparison
                PatternElement::Bounded { min: _, max } => {
                    // Worst case: max iterations
                    *max as u64 * 2
                }
            };
        }

        total_cycles
    }

    /// Check if pattern execution time is within acceptable bounds
    pub fn is_fast_pattern(pattern: &[PatternElement]) -> bool {
        const MAX_CYCLES: u64 = 1000; // Arbitrary threshold
        Self::estimate_cycles(pattern) <= MAX_CYCLES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combinator_dsl::patterns::*;

    #[test]
    fn test_constraint_validation() {
        let mut enforcer = ConstraintEnforcer::new();

        // Valid pattern
        let valid_pattern = vec![
            PatternElement::Byte(0x05),
            PatternElement::Any,
        ];
        assert_eq!(enforcer.validate_pattern(&valid_pattern), ConstraintResult::Valid);

        // Too long pattern
        let long_pattern = vec![PatternElement::Any; MAX_PATTERN_LENGTH + 1];
        match enforcer.validate_pattern(&long_pattern) {
            ConstraintResult::TooLong { actual, max } => {
                assert_eq!(actual, MAX_PATTERN_LENGTH + 1);
                assert_eq!(max, MAX_PATTERN_LENGTH);
            }
            _ => panic!("Expected TooLong error"),
        }

        // Range too large
        let large_range_pattern = vec![PatternElement::Range(0, MAX_RANGE_SIZE)];
        match enforcer.validate_pattern(&large_range_pattern) {
            ConstraintResult::RangeTooLarge { actual, max } => {
                assert_eq!(actual, MAX_RANGE_SIZE + 1);
                assert_eq!(max, MAX_RANGE_SIZE);
            }
            _ => panic!("Expected RangeTooLarge error"),
        }
    }

    #[test]
    fn test_constrained_combinator() {
        let socks5_combinator = socks5();
        assert_eq!(socks5_combinator.validate_constraints(), ConstraintResult::Valid);
        assert!(socks5_combinator.is_bounded());

        let constrained = socks5_combinator.with_constraints();
        assert_eq!(constrained.validate_constraints(), ConstraintResult::Valid);
    }

    #[test]
    fn test_bounded_pattern_builder() {
        let builder = BoundedPatternBuilder::new();
        
        // Should succeed with reasonable inputs
        let result = builder
            .byte_sequence(b"GET ")
            .unwrap()
            .bounded_any(0, 4)
            .unwrap()
            .build(Protocol::Http);
        
        assert!(result.is_ok());

        // Should fail with unbounded pattern
        let builder2 = BoundedPatternBuilder::new();
        let result2 = builder2.bounded_any(0, usize::MAX);
        assert!(result2.is_err());
    }

    #[test]
    fn test_safe_patterns() {
        use safe_patterns::*;

        let safe_socks5 = safe_socks5();
        assert_eq!(safe_socks5.validate_constraints(), ConstraintResult::Valid);
        assert!(safe_socks5.is_bounded());

        let safe_http = safe_http_get();
        assert_eq!(safe_http.validate_constraints(), ConstraintResult::Valid);
        assert!(safe_http.is_bounded());

        let safe_tls = safe_tls();
        assert_eq!(safe_tls.validate_constraints(), ConstraintResult::Valid);
        assert!(safe_tls.is_bounded());
    }

    #[test]
    fn test_execution_time_estimation() {
        let simple_pattern = vec![
            PatternElement::Byte(0x05),
            PatternElement::Any,
        ];
        
        let cycles = ExecutionTimeEstimator::estimate_cycles(&simple_pattern);
        assert!(cycles > 0);
        assert!(ExecutionTimeEstimator::is_fast_pattern(&simple_pattern));

        let expensive_pattern = vec![
            PatternElement::Bounded { min: 0, max: 1000 },
        ];
        
        let expensive_cycles = ExecutionTimeEstimator::estimate_cycles(&expensive_pattern);
        assert!(expensive_cycles > cycles);
        assert!(!ExecutionTimeEstimator::is_fast_pattern(&expensive_pattern));
    }

    #[test]
    fn test_pattern_constraining() {
        let enforcer = ConstraintEnforcer::new();
        
        // Test constraining a large range
        let large_pattern = vec![PatternElement::Range(0, 255)];
        let constrained = enforcer.constrain_pattern(&large_pattern);
        
        match &constrained[0] {
            PatternElement::Range(start, end) => {
                assert_eq!(*start, 0);
                assert!(*end < 255);
                assert!(end - start + 1 <= MAX_RANGE_SIZE);
            }
            _ => panic!("Expected constrained range"),
        }
    }

    #[test]
    fn test_lookahead_calculation() {
        let enforcer = ConstraintEnforcer::new();
        
        let pattern = vec![
            PatternElement::Byte(0x16),
            PatternElement::Byte(0x03),
            PatternElement::Bounded { min: 1, max: 4 },
        ];
        
        let lookahead = enforcer.calculate_lookahead_requirement(&pattern);
        assert_eq!(lookahead, 6); // 1 + 1 + 4
    }
}