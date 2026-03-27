#![no_main]
use libfuzzer_sys::fuzz_target;
use reme_bundle::BundleReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = BundleReader::open(data) {
        while let Ok(Some(_)) = reader.next_frame() {}
        let _ = reader.verify_checksum();
    }
});
