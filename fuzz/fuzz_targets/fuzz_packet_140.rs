#![no_main]
use discv5::packet::{Packet, IV_LENGTH, STATIC_HEADER_LENGTH, MESSAGE_NONCE_LENGTH};
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
    if data.len() > IV_LENGTH + STATIC_HEADER_LENGTH + MESSAGE_NONCE_LENGTH {

        let id: NodeId = node_key_1().public().into();

        // Prepare fixed length Magic
        let mut magic_data = [0u8; IV_LENGTH + STATIC_HEADER_LENGTH + MESSAGE_NONCE_LENGTH];
        magic_data.copy_from_slice(&data[..IV_LENGTH + STATIC_HEADER_LENGTH + MESSAGE_NONCE_LENGTH]);

        // Set data tag to 140 (bytes / list)
        // let mut data_140 = data[MAGIC_LENGTH..].to_vec();
        // data_140[TAG_LENGTH] = 140;

        // Fuzz decode packet
        if let Ok(packet) = Packet::decode(&id, &magic_data) {
            packet.encode(&id);
        }
    }
});
