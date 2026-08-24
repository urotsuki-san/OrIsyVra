#![no_main]

use libfuzzer_sys::fuzz_target;
use orisyvra::decode_keycard_image;

fuzz_target!(|data: &[u8]| {
    let _ = decode_keycard_image(data);
});
