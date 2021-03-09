mod ncm;

use wasm_bindgen::prelude::*;
use std::sync::Once;
use crate::ncm::{NcmDump, DumpOutput};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
pub fn initialize() {
    console_error_panic_hook::set_once();
    Once::new().call_once(|| {
        wasm_logger::init(Default::default());
    });
}

#[wasm_bindgen]
pub fn dump(data: Vec<u8>) -> DumpOutput {
    NcmDump::new_from_memory(data).dump()
}
