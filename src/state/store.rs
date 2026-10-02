//! Bounded envelope loading and atomic replacement with integrity checks and durable syncs.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use prost::Message;
use sha2::{Digest, Sha256};

use super::format::{
    DIGEST_BYTES, MAGIC, MAX_STATE_BYTES, PersistedState, StateError, validate_state,
};

#[derive(Clone, Debug)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<PersistedState>, StateError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((MAX_STATE_BYTES + MAGIC.len() + 4 + DIGEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_BYTES + MAGIC.len() + 4 + DIGEST_BYTES {
            return Err(StateError::Invalid("state exceeds the configured bound"));
        }
        let minimum = MAGIC.len() + 4 + DIGEST_BYTES;
        if bytes.len() < minimum || &bytes[..MAGIC.len()] != MAGIC {
            return Err(StateError::Invalid("state envelope header"));
        }
        let length_offset = MAGIC.len();
        let payload_length = u32::from_be_bytes(
            bytes[length_offset..length_offset + 4]
                .try_into()
                .map_err(|_| StateError::Invalid("state length"))?,
        ) as usize;
        let payload_start = length_offset + 4;
        let payload_end = payload_start
            .checked_add(payload_length)
            .ok_or(StateError::Invalid("state length overflow"))?;
        if payload_length > MAX_STATE_BYTES || payload_end + DIGEST_BYTES != bytes.len() {
            return Err(StateError::Invalid("state payload length"));
        }
        let expected_digest = Sha256::digest(&bytes[payload_start..payload_end]);
        if expected_digest.as_slice() != &bytes[payload_end..] {
            return Err(StateError::Invalid("state integrity digest"));
        }
        let state = PersistedState::decode(&bytes[payload_start..payload_end])?;
        validate_state(&state)?;
        Ok(Some(state))
    }

    pub fn replace(&self, state: &PersistedState) -> Result<(), StateError> {
        validate_state(state)?;
        let payload = state.encode_to_vec();
        if payload.len() > MAX_STATE_BYTES {
            return Err(StateError::Invalid("state exceeds the configured bound"));
        }
        let mut envelope = Vec::with_capacity(MAGIC.len() + 4 + payload.len() + DIGEST_BYTES);
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&payload);
        envelope.extend_from_slice(&Sha256::digest(&payload));

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&envelope)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Writer validation must preserve good files; reader validation must reject integrity-valid wire inputs.

    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use prost::Message;
    use sha2::{Digest, Sha256};

    use crate::control::{EdgeConfiguration, ProductIdentity};
    use crate::state::{PersistedDrain, PersistedState, PersistedTombstone, StateError};

    use super::StateStore;

    fn valid_state() -> PersistedState {
        PersistedState {
            authority_epoch: 3,
            active: vec![EdgeConfiguration {
                identity: Some(ProductIdentity {
                    traffic_target_id: "target".into(),
                    ..Default::default()
                }),
                controller_epoch: 3,
                ..Default::default()
            }],
            tombstones: vec![PersistedTombstone {
                target_id: "withdrawn-target".into(),
                controller_epoch: 3,
                generation: 4,
                configuration_hash: vec![7; 32],
            }],
            drains: vec![PersistedDrain {
                target_id: "draining-target".into(),
                controller_epoch: 3,
                generation: 1,
                configuration_hash: vec![7; 32],
                drain_until_unix_ms: 1,
            }],
        }
    }

    fn invalid_states() -> Vec<(&'static str, PersistedState, &'static str)> {
        type InvalidStateCase = (&'static str, fn(&mut PersistedState), &'static str);
        let cases: [InvalidStateCase; 9] = [
            (
                "missing active identity",
                |state| state.active[0].identity = None,
                "active configuration identity",
            ),
            (
                "empty active target",
                |state| {
                    state.active[0]
                        .identity
                        .as_mut()
                        .expect("fixture identity")
                        .traffic_target_id
                        .clear();
                },
                "active configuration identity",
            ),
            (
                "duplicate active target",
                |state| state.active.push(state.active[0].clone()),
                "active configuration identity",
            ),
            (
                "active authority exceeds retained authority",
                |state| state.active[0].controller_epoch = 4,
                "active authority exceeds retained authority",
            ),
            (
                "short tombstone hash",
                |state| {
                    state.tombstones[0].configuration_hash.pop();
                },
                "tombstone identity",
            ),
            (
                "tombstone authority exceeds retained authority",
                |state| state.tombstones[0].controller_epoch = 4,
                "tombstone identity",
            ),
            (
                "duplicate drain target",
                |state| state.drains.push(state.drains[0].clone()),
                "drain identity",
            ),
            (
                "zero drain deadline",
                |state| state.drains[0].drain_until_unix_ms = 0,
                "drain identity",
            ),
            (
                "negative drain deadline",
                |state| state.drains[0].drain_until_unix_ms = -1,
                "drain identity",
            ),
        ];
        cases
            .into_iter()
            .map(|(case, mutate, reason)| {
                let mut state = valid_state();
                mutate(&mut state);
                (case, state, reason)
            })
            .collect()
    }

    fn encode_envelope(state: &PersistedState) -> Vec<u8> {
        let payload = state.encode_to_vec();
        let mut envelope = b"APOLLO-EDGE-STATE\n".to_vec();
        let length = u32::try_from(payload.len()).expect("fixture payload length");
        envelope.extend_from_slice(&length.to_be_bytes());
        envelope.extend_from_slice(&payload);
        envelope.extend_from_slice(&Sha256::digest(&payload));
        envelope
    }

    #[test]
    fn replacement_round_trip_is_integrity_checked() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway.state");
        let store = StateStore::new(&path);
        let state = valid_state();
        store.replace(&state).expect("state replacement");
        assert_eq!(store.load().expect("state load"), Some(state));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn invalid_replacements_preserve_the_previous_good_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway.state");
        let store = StateStore::new(&path);
        let good_state = valid_state();
        store.replace(&good_state).expect("valid state replacement");
        assert_eq!(
            store.load().expect("valid state load"),
            Some(good_state.clone())
        );
        let good_bytes = fs::read(&path).expect("good state bytes");

        for (case, state, reason) in invalid_states() {
            let error = store.replace(&state).expect_err(case);
            assert!(
                matches!(error, StateError::Invalid(actual) if actual == reason),
                "{case}: expected Invalid({reason:?}), got {error:?}"
            );
            assert_eq!(
                fs::read(&path).expect("retained state bytes"),
                good_bytes,
                "{case}"
            );
            assert_eq!(
                store.load().expect("retained state load"),
                Some(good_state.clone()),
                "{case}"
            );
        }
    }

    #[test]
    fn integrity_valid_envelopes_still_require_semantically_valid_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway.state");
        let store = StateStore::new(&path);
        let good_state = valid_state();
        fs::write(&path, encode_envelope(&good_state)).expect("valid independent envelope");
        assert_eq!(
            store.load().expect("valid independent state load"),
            Some(good_state)
        );

        for (case, state, reason) in invalid_states() {
            fs::write(&path, encode_envelope(&state)).expect("invalid independent envelope");
            let error = store.load().expect_err(case);
            assert!(
                matches!(error, StateError::Invalid(actual) if actual == reason),
                "{case}: expected Invalid({reason:?}), got {error:?}"
            );
        }
    }

    #[test]
    fn tampering_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway.state");
        let store = StateStore::new(&path);
        store
            .replace(&PersistedState::default())
            .expect("state replacement");
        let mut bytes = fs::read(&path).expect("state bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).expect("tampered state");
        assert!(matches!(
            store.load(),
            Err(StateError::Invalid("state integrity digest"))
        ));
    }
}
