#![no_main]
use libfuzzer_sys::fuzz_target;
use reme_message::wire::WirePayload;

fuzz_target!(|data: &[u8]| {
    let _ = WirePayload::decode(data);
});
