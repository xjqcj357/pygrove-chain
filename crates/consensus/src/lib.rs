//! Consensus: PoW seal, Bitcoin retarget, the Accordion, the Reflection, emission schedule.

pub mod accordion;
pub mod emission;
pub mod pow;
pub mod reflection;
pub mod retarget;

pub use accordion::{evaluate, AccordionOutcome, AccordionParams, Regime};
pub use emission::{current_reward, scheduled_supply_at, EmissionParams};
pub use pow::{hash_header, meets_target, target_from_bits};
pub use reflection::{compute_stability_bias, ReflectWindow, Reflection};
pub use retarget::{bitcoin_retarget, clamp_retarget};
