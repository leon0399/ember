#![no_main]
use libfuzzer_sys::fuzz_target;
use reme_message::InnerEnvelope;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<InnerEnvelope>(data);
});
