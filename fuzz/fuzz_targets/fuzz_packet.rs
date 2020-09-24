#![no_main]
use discv5::packet::Packet;
use libfuzzer_sys::fuzz_target;
use discv5::enr::{EnrKey, NodeId, CombinedKey};

fn hex_decode(x: &'static str) -> Vec<u8> {
    hex::decode(x).unwrap()
}

fn node_key_1() -> CombinedKey {
    CombinedKey::secp256k1_from_bytes(&mut hex_decode(
        "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
    ))
    .unwrap()
}


fuzz_target!(|data: &[u8]| {
    if data.len() > 32 {
        let id: NodeId = node_key_1().public().into();
        let mut magic_data = [0u8; 32];
        magic_data.copy_from_slice(&data[..32]);
        if let Ok(packet) = Packet::decode(&id, &magic_data) {
            packet.encode(&id);
        }
    }
});
