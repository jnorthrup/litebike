//! Web Model Cards - Specialized metadata cache for agent reasoning

use crate::keymux::types::{Pricing, WebModelCard};
use parking_lot::RwLock;
use std::collections::HashMap;

pub struct ModelCardStore {
    cards: RwLock<HashMap<String, WebModelCard>>,
}

impl ModelCardStore {
    pub fn new() -> Self {
        let store = Self {
            cards: RwLock::new(HashMap::new()),
        };
        store.load_defaults();
        store
    }

    fn load_defaults(&self) {
        let mut cards = self.cards.write();

        cards.insert(
            "anthropic/claude-3-5-sonnet".to_string(),
            WebModelCard {
                tags: vec![
                    "reasoning".to_string(),
                    "coding".to_string(),
                    "vision".to_string(),
                ],
                context_window: 200_000,
                pricing: Some(Pricing {
                    prompt: 3.0,
                    completion: 15.0,
                    unit: "1M tokens".to_string(),
                }),
                reasoning_depth: 9,
                code_native: true,
            },
        );

        cards.insert(
            "openai/gpt-4o".to_string(),
            WebModelCard {
                tags: vec![
                    "multimodal".to_string(),
                    "fast".to_string(),
                    "general".to_string(),
                ],
                context_window: 128_000,
                pricing: Some(Pricing {
                    prompt: 5.0,
                    completion: 15.0,
                    unit: "1M tokens".to_string(),
                }),
                reasoning_depth: 8,
                code_native: true,
            },
        );
    }

    pub fn get_all_models(&self) -> Vec<String> {
        self.cards.read().keys().cloned().collect()
    }

    pub fn get_card(&self, model_id: &str) -> Option<WebModelCard> {
        self.cards.read().get(model_id).cloned()
    }
}

impl Default for ModelCardStore {
    fn default() -> Self {
        Self::new()
    }
}
