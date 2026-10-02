//! Persisted gateway authority and atomic, integrity-checked state storage.

mod format;
mod store;

pub use format::{
    MAX_ACTIVE_CONFIGURATIONS, MAX_STATE_BYTES, MAX_TOMBSTONES, PersistedDrain, PersistedState,
    PersistedTombstone, StateError,
};
pub use store::StateStore;
