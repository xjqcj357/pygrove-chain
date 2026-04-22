//! Consensus: PoW seal, Bitcoin retarget, the Accordion, the Reflection, emission schedule.

pub mod accordion;
pub mod emission;
pub mod pow;
pub mod reflection;
pub mod retarget;

pub use accordion::{AccordionOutcome, AccordionParams};
pub use emission::{Emission, EmissionParams};
pub use pow::{hash_header, meets_target};
pub use reflection::{ReflectWindow, Reflection};
pub use retarget::{bitcoin_retarget, clamp_retarget};
