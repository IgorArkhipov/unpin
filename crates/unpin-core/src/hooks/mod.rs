//! Normalized hook inventory, policy, and dispatch contracts.
//!
//! Provider configuration is untrusted input. Discovery keeps provider-native
//! definitions opaque and exposes only bounded metadata plus fingerprints.
//! Gateway execution requires a separately reviewed structured action.

mod dispatcher;
mod model;
mod policy;
mod trust;

pub use dispatcher::*;
pub use model::*;
pub use policy::*;
pub use trust::*;
