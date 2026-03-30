#![no_main]
use libfuzzer_sys::fuzz_target;
use ember_message::OuterEnvelope;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<OuterEnvelope>(data);
});
