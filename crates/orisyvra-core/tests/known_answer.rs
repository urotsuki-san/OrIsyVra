use orisyvra_core::{derive_key, mac32, permute, prf_parts, Domain, KEY_SIZE};

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).expect("valid vector hex");
    }
    output
}

#[test]
fn permutation_vectors() {
    let mut zero = [0_u64; 12];
    permute(&mut zero);
    assert_eq!(
        zero,
        [
            0x3846_133e_797d_6d51,
            0xb28c_147f_6832_4d17,
            0xc19c_d0a7_81d4_7cca,
            0x0b68_fa2c_dc2a_14a7,
            0x6dde_95f5_9601_0e75,
            0x840a_d692_6f4d_c10c,
            0x4722_6a02_f515_115d,
            0x767a_2650_8f48_8149,
            0x3f3d_6543_d1b9_6ecb,
            0x8f27_e3c8_b47e_68cc,
            0x4a73_140a_d4e9_8f65,
            0xabe4_c52d_3c8e_3f67,
        ]
    );

    let mut incremental = core::array::from_fn(|index| index as u64);
    permute(&mut incremental);
    assert_eq!(
        incremental,
        [
            0x621a_dd7f_3292_1b34,
            0x043c_a7e7_f119_964a,
            0x578a_c3bc_498a_bfbf,
            0x4778_7b2c_e97e_7d4e,
            0xf9bd_c20c_3fed_eeee,
            0x1616_ad44_2b25_ffb3,
            0x2aa2_6ef8_bed4_df2d,
            0xbc33_bbad_aad3_5aaa,
            0xb505_db39_12ab_2b20,
            0x32de_b4ce_d963_c6af,
            0x58a7_2d91_f622_159e,
            0x774c_47b5_657a_7c93,
        ]
    );
}

#[test]
fn keyed_vectors() {
    let key: [u8; KEY_SIZE] = core::array::from_fn(|index| index as u8);
    let suffix: [u8; 17] = core::array::from_fn(|index| index as u8);
    let mut stream = [0_u8; 96];
    prf_parts(
        &key,
        Domain::Stream,
        &[b"OrIsyVra vector", &suffix],
        &mut stream,
    );
    assert_eq!(stream, decode_hex("b26e91ca449ebd4fe9a74bee9cdcebc607782b4a3948750fd97c1c3f0841527485fcf9fc7415d32136f99a4ae35fde93ab7ff0d91ce92782b94633f931f6908faef6a7361e4338d486478b0f27da118e5524a8f056cf0f4fca5727dc95904f71"));

    assert_eq!(
        mac32(&key, Domain::RecordSiv, &[b"context", b"plaintext"]),
        decode_hex("7020174e0eccb71e4448bed7f0e5938d92feb722a49ee9407cb37546d6ac0e6c")
    );
    assert_eq!(
        derive_key(&key, b"label", b"context"),
        decode_hex("1f49e59ef96bec5bca8c126384c06f3580cd8dda41568cf56b1a368c4fe37e3b951b8598e5a9e4052ab424bb8f2a2a7b")
    );
}
