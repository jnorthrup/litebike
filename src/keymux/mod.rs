pub mod cards;
pub mod dsel;
pub mod facade;
pub mod protocols;
pub mod types;

pub use cards::ModelCardStore;
pub use dsel::{DSELBuilder, ProviderPotential, ProviderSelectionRule, QuotaContainer, RuleEngine};
pub use facade::ModelFacade;
pub use protocols::ModelMapping;
pub use types::{ModelId, ModelInfo, WebModelCard};

// Re-export from literbike (single source of truth)
// literbike hosts model_mux and keymux precedence logic
pub use literbike::model_mux::{
    UnifiedMuxState, PrecedenceMode, PrecedenceRule, ProviderPrecedence,
    DecisionSource, RoutingDecision
};
