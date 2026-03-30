#![no_main]
use libfuzzer_sys::fuzz_target;
use ember_message::tombstone::SignedAckTombstone;

fuzz_target!(|data: &[u8]| {
    let _ = SignedAckTombstone::from_bytes(data);
});
