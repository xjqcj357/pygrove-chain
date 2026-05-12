//! Consensus: PoW seal, Bitcoin retarget, the Accordion, the Reflection, emission schedule.

pub mod accordion;
pub mod asert;
pub mod emission;
pub mod pow;
pub mod reflection;
pub mod retarget;

pub use accordion::{evaluate, AccordionOutcome, AccordionParams, Regime};
pub use asert::next_bits_from_parent;
pub use emission::{current_reward, scheduled_supply_at, EmissionParams};
pub use pow::{bits_from_target, hash_header, meets_target, target_from_bits};
pub use reflection::{compute_stability_bias, ReflectWindow, Reflection};
pub use retarget::{bitcoin_retarget, clamp_retarget};
