#![no_main]
use libfuzzer_sys::fuzz_target;
use reme_message::tombstone::SignedAckTombstone;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<SignedAckTombstone>(data);
});
