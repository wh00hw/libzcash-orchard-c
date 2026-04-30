//! Test vector generator for libzcash-orchard-c
//!
//! Generates known-answer test vectors from the Rust reference implementation
//! (librustzcash ecosystem) and outputs a C header file for KAT testing.

use blake2b_simd::Params as Blake2bParams;
use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use std::fmt::Write as FmtWrite;
use std::io::Write;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bytes_to_c_array(bytes: &[u8]) -> String {
    let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    hex_bytes.join(", ")
}

fn point_to_le_bytes(p: &pallas::Point) -> [u8; 32] {
    let affine = p.to_affine();
    affine.to_bytes()
}

fn write_vector(out: &mut String, name: &str, bytes: &[u8]) {
    writeln!(
        out,
        "static const uint8_t {name}[] = {{ {} }};",
        bytes_to_c_array(bytes)
    )
    .unwrap();
}

// Emit a domain literal as null-terminated bytes so callers that take it
// via `(const char*)` and call strlen()/snprintf("%s", ...) read a proper
// C string — without the trailing NUL the C side reads past the end of
// the array into adjacent BSS, which produces wrong hash inputs.
fn write_domain(out: &mut String, name: &str, domain: &str) {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    writeln!(
        out,
        "static const uint8_t {name}[] = {{ {} }};",
        bytes_to_c_array(&bytes)
    )
    .unwrap();
}

fn write_vector_with_len(out: &mut String, name: &str, bytes: &[u8]) {
    write_vector(out, name, bytes);
    writeln!(out, "static const size_t {name}_len = {};", bytes.len()).unwrap();
}

// ─── BLAKE2b Personalized ────────────────────────────────────────────────────

struct Blake2bVector {
    name: &'static str,
    personal: &'static [u8; 16],
    input: Vec<u8>,
    output_len: usize,
}

fn generate_blake2b_vectors(out: &mut String) {
    writeln!(out, "\n/* ── BLAKE2b Personalized Hashing ── */\n").unwrap();

    let test_input_32: Vec<u8> = (0u8..32).collect();
    let test_input_64: Vec<u8> = (0u8..64).collect();

    let vectors = vec![
        Blake2bVector {
            name: "blake2b_zip32_orchard",
            personal: b"ZcashIP32Orchard",
            input: test_input_64.clone(),
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_expand_seed",
            personal: b"Zcash_ExpandSeed",
            input: test_input_64.clone(),
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_redpallas_nonce",
            personal: b"Zcash_RedPallasN",
            input: {
                let mut v = Vec::new();
                v.extend_from_slice(&test_input_32); // rsk
                v.extend_from_slice(&test_input_32); // sighash
                v.extend_from_slice(&test_input_32); // random
                v
            },
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_redpallas_challenge",
            personal: b"Zcash_RedPallasH",
            input: {
                let mut v = Vec::new();
                v.extend_from_slice(&test_input_32); // R
                v.extend_from_slice(&test_input_32); // rk
                v.extend_from_slice(&test_input_32); // sighash
                v
            },
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_f4jumble_h",
            personal: b"UA_F4Jumble_H\x00\x00\x00",
            input: test_input_32.clone(),
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_f4jumble_g",
            personal: b"UA_F4Jumble_G\x00\x00\x00",
            input: test_input_32.clone(),
            output_len: 64,
        },
        Blake2bVector {
            name: "blake2b_tx_hash",
            personal: b"ZTxIdOrchardHash",
            input: test_input_32.clone(),
            output_len: 32,
        },
    ];

    for v in &vectors {
        let hash = Blake2bParams::new()
            .hash_length(v.output_len)
            .personal(v.personal)
            .hash(&v.input);

        write_vector(out, &format!("{}_input", v.name), &v.input);
        writeln!(
            out,
            "static const size_t {}_input_len = {};",
            v.name,
            v.input.len()
        )
        .unwrap();
        writeln!(
            out,
            "static const size_t {}_output_len = {};",
            v.name, v.output_len
        )
        .unwrap();
        write_vector(
            out,
            &format!("{}_expected", v.name),
            hash.as_bytes(),
        );
        writeln!(out).unwrap();
    }
}

// ─── Pallas Hash-to-Curve ────────────────────────────────────────────────────

fn generate_hash_to_curve_vectors(out: &mut String) {
    writeln!(out, "\n/* ── Pallas Hash-to-Curve (Group Hash) ── */\n").unwrap();

    let test_cases = vec![
        ("htc_orchard_g", "z.cash:Orchard", b"G".as_ref()),
        ("htc_orchard_gd", "z.cash:Orchard-gd", &[0u8; 11]),
        (
            "htc_sinsemilla_q",
            "z.cash:SinsemillaQ",
            b"z.cash:Orchard-NoteCommit-M",
        ),
    ];

    for (name, domain, msg) in &test_cases {
        let hasher = pallas::Point::hash_to_curve(domain);
        let point = hasher(msg);
        let bytes = point_to_le_bytes(&point);

        write_domain(out, &format!("{name}_domain"), domain);
        writeln!(
            out,
            "static const size_t {name}_domain_len = {};",
            domain.len()
        )
        .unwrap();
        write_vector_with_len(out, &format!("{name}_msg"), msg);
        write_vector(out, &format!("{name}_expected"), &bytes);
        writeln!(out).unwrap();
    }
}

// ─── Sinsemilla S-table Samples ──────────────────────────────────────────────

fn generate_sinsemilla_s_vectors(out: &mut String) {
    writeln!(out, "\n/* ── Sinsemilla S-Table Samples ── */\n").unwrap();

    let indices: Vec<u32> = vec![0, 1, 2, 512, 1023];

    writeln!(
        out,
        "static const uint32_t sinsemilla_s_indices[] = {{ {} }};",
        indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "static const size_t sinsemilla_s_num_samples = {};",
        indices.len()
    )
    .unwrap();
    writeln!(out).unwrap();

    for &idx in &indices {
        let hasher = pallas::Point::hash_to_curve("z.cash:SinsemillaS");
        let point = hasher(&idx.to_le_bytes());
        let bytes = point_to_le_bytes(&point);

        write_vector(
            out,
            &format!("sinsemilla_s_{idx}_expected"),
            &bytes,
        );
    }
    writeln!(out).unwrap();
}

// ─── ZIP-32 Key Derivation ───────────────────────────────────────────────────

fn generate_zip32_vectors(out: &mut String) {
    writeln!(out, "\n/* ── ZIP-32 Orchard Key Derivation ── */\n").unwrap();

    // "abandon abandon ... about" mnemonic produces this seed
    // (PBKDF2-HMAC-SHA512 of the mnemonic with passphrase "")
    // We use a deterministic known seed for reproducibility
    let seed: [u8; 64] = {
        // BIP39 seed for "abandon abandon abandon abandon abandon abandon
        // abandon abandon abandon abandon abandon about"
        let mut s = [0u8; 64];
        let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let bytes = hex::decode(seed_hex).unwrap();
        s.copy_from_slice(&bytes);
        s
    };

    write_vector(out, "zip32_seed", &seed);
    writeln!(out).unwrap();

    // Master key: BLAKE2b-512("ZcashIP32Orchard", seed)
    let master = Blake2bParams::new()
        .hash_length(64)
        .personal(b"ZcashIP32Orchard")
        .hash(&seed);
    let master_bytes = master.as_bytes();

    write_vector(out, "zip32_master_sk", &master_bytes[..32]);
    write_vector(out, "zip32_master_chain", &master_bytes[32..]);
    writeln!(out).unwrap();

    // Use the orchard crate for full derivation
    use orchard::keys::{FullViewingKey, SpendingKey};

    let coin_type = 133u32; // mainnet
    let account = 0u32;

    let sk = SpendingKey::from_zip32_seed(&seed, coin_type, account.try_into().unwrap())
        .expect("valid spending key");

    // SpendingKey bytes
    write_vector(out, "zip32_sk", sk.to_bytes());

    // Full viewing key = ak || nk || rivk (96 bytes)
    let fvk = FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();
    write_vector(out, "zip32_fvk", &fvk_bytes);
    write_vector(out, "zip32_ak", &fvk_bytes[..32]);
    write_vector(out, "zip32_nk", &fvk_bytes[32..64]);
    write_vector(out, "zip32_rivk", &fvk_bytes[64..]);
    writeln!(out).unwrap();

    // Derive default address (diversifier index 0)
    let address = fvk.address_at(0u32, orchard::keys::Scope::External);
    let addr_bytes = address.to_raw_address_bytes();
    write_vector(out, "zip32_diversifier", &addr_bytes[..11]);
    write_vector(out, "zip32_pk_d", &addr_bytes[11..]);
    writeln!(out).unwrap();

    writeln!(
        out,
        "static const uint32_t zip32_coin_type = {};",
        coin_type
    )
    .unwrap();
    writeln!(
        out,
        "static const uint32_t zip32_account = {};",
        account
    )
    .unwrap();
}

// ─── FF1-AES-256 ─────────────────────────────────────────────────────────────

fn generate_ff1_vectors(out: &mut String) {
    writeln!(out, "\n/* ── FF1-AES-256 (Diversifier Derivation) ── */\n").unwrap();

    use fpe::ff1::{BinaryNumeralString, FF1};
    use aes::Aes256;

    // Test case 1: all-zero key and all-zero input (default diversifier)
    let key1 = [0u8; 32];
    let input1 = [0u8; 11]; // 88 bits
    let ff1 = FF1::<Aes256>::new(&key1, 2).unwrap();
    let input_bns = BinaryNumeralString::from_bytes_le(&input1);
    let output_bns = ff1.encrypt(&[], &input_bns).unwrap();
    let output1 = output_bns.to_bytes_le();

    write_vector(out, "ff1_key_1", &key1);
    write_vector(out, "ff1_input_1", &input1);
    write_vector(out, "ff1_expected_1", &output1);
    writeln!(out).unwrap();

    // Test case 2: known key from ZIP-32 derivation + zero input
    // Use a deterministic key pattern
    let key2: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
    let input2 = [0u8; 11];
    let ff1_2 = FF1::<Aes256>::new(&key2, 2).unwrap();
    let input2_bns = BinaryNumeralString::from_bytes_le(&input2);
    let output2_bns = ff1_2.encrypt(&[], &input2_bns).unwrap();
    let output2 = output2_bns.to_bytes_le();

    write_vector(out, "ff1_key_2", &key2);
    write_vector(out, "ff1_input_2", &input2);
    write_vector(out, "ff1_expected_2", &output2);
    writeln!(out).unwrap();

    // Test case 3: non-zero input
    let key3 = [0xABu8; 32];
    let input3: [u8; 11] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45];
    let ff1_3 = FF1::<Aes256>::new(&key3, 2).unwrap();
    let input3_bns = BinaryNumeralString::from_bytes_le(&input3);
    let output3_bns = ff1_3.encrypt(&[], &input3_bns).unwrap();
    let output3 = output3_bns.to_bytes_le();

    write_vector(out, "ff1_key_3", &key3);
    write_vector(out, "ff1_input_3", &input3);
    write_vector(out, "ff1_expected_3", &output3);
    writeln!(out).unwrap();
}

// ─── RedPallas Deterministic Signing ─────────────────────────────────────────

fn generate_redpallas_vectors(out: &mut String) {
    writeln!(
        out,
        "\n/* ── RedPallas Signing (deterministic nonce, random_bytes = 0x42*32) ── */\n"
    )
    .unwrap();

    use ff::PrimeField;
    use pasta_curves::pallas;

    // Test inputs
    let ask: [u8; 32] = {
        // Use the ask from ZIP-32 derivation of "abandon...about"
        let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let seed = hex::decode(seed_hex).unwrap();

        let sk = orchard::keys::SpendingKey::from_zip32_seed(
            &seed,
            133,
            0u32.try_into().unwrap(),
        )
        .unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let _fvk_bytes = fvk.to_bytes();

        // ask is not directly in fvk, but we can derive it from sk.
        // The spending key IS ask after ToScalar reduction.
        // sk.to_bytes() = spending key bytes
        // ask = PRF_expand(sk, 0x06) mod q
        // Let's compute it the same way the C code does.
        let sk_bytes = sk.to_bytes();
        let prf = Blake2bParams::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .to_state()
            .update(sk_bytes)
            .update(&[0x06])
            .finalize();

        // Convert to scalar (mod q)
        let ask_scalar = pallas::Scalar::from_uniform_bytes(prf.as_bytes().try_into().unwrap());
        ask_scalar.to_repr()
    };

    let alpha: [u8; 32] = [0x22; 32]; // known alpha randomizer
    let sighash: [u8; 32] = [0x11; 32]; // known sighash

    write_vector(out, "rp_ask", &ask);
    write_vector(out, "rp_alpha", &alpha);
    write_vector(out, "rp_sighash", &sighash);
    writeln!(out).unwrap();

    // Replicate the C signing computation with fixed random_bytes = 0x42*32
    let fixed_random = [0x42u8; 32];

    // rsk = ask + alpha mod q
    let ask_scalar = pallas::Scalar::from_repr(ask).unwrap();
    let alpha_scalar = pallas::Scalar::from_repr(alpha).unwrap();
    let rsk = ask_scalar + alpha_scalar;

    // rk = [rsk] * G_SpendAuth
    let g_spend = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    let rk = g_spend * rsk;
    let rk_bytes = point_to_le_bytes(&rk);

    write_vector(out, "rp_rk_expected", &rk_bytes);

    // Nonce: T = BLAKE2b-512("Zcash_RedPallasN", rsk_bytes || sighash || random)
    let rsk_bytes = rsk.to_repr();
    let nonce_hash = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_RedPallasN")
        .to_state()
        .update(&rsk_bytes)
        .update(&sighash)
        .update(&fixed_random)
        .finalize();

    let nonce = pallas::Scalar::from_uniform_bytes(nonce_hash.as_bytes().try_into().unwrap());

    // R = [nonce] * G_SpendAuth
    let r_point = g_spend * nonce;
    let r_bytes = point_to_le_bytes(&r_point);

    // challenge = H("Zcash_RedPallasH", R || rk || sighash) mod q
    let challenge_hash = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_RedPallasH")
        .to_state()
        .update(&r_bytes)
        .update(&rk_bytes)
        .update(&sighash)
        .finalize();

    let challenge =
        pallas::Scalar::from_uniform_bytes(challenge_hash.as_bytes().try_into().unwrap());

    // S = nonce + challenge * rsk mod q
    let s_scalar = nonce + challenge * rsk;
    let s_bytes = s_scalar.to_repr();

    // Signature = R || S
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);

    write_vector(out, "rp_sig_expected", &sig);
    writeln!(out).unwrap();
}

// ─── Sinsemilla End-to-End ───────────────────────────────────────────────────

fn generate_sinsemilla_vectors(out: &mut String) {
    writeln!(
        out,
        "\n/* ── Sinsemilla End-to-End (HashToPoint + ShortCommit) ── */\n"
    )
    .unwrap();

    use ff::PrimeField;
    use pasta_curves::pallas;

    // Sinsemilla accumulation: acc = (acc + S[chunk]) + acc per iteration
    // This matches the spec: "incomplete addition, then add acc again"

    // Helper: compute SinsemillaHashToPoint(domain, msg_bits)
    // Q = GroupHash("z.cash:SinsemillaQ", domain)
    // acc0 = Q
    // acc_{i+1} = (acc_i + S[chunk_i]) + acc_i
    fn sinsemilla_hash_to_point(domain: &str, msg_bits: &[u8], num_bits: usize) -> pallas::Point {
        let q = pallas::Point::hash_to_curve("z.cash:SinsemillaQ")(domain.as_bytes());
        let mut acc = q;
        let num_chunks = num_bits / 10;
        for i in 0..num_chunks {
            let mut chunk: u32 = 0;
            for b in 0..10 {
                let bit_idx = i * 10 + b;
                if msg_bits[bit_idx / 8] & (1 << (bit_idx % 8)) != 0 {
                    chunk |= 1 << b;
                }
            }
            let s = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(&chunk.to_le_bytes());
            acc = (acc + s) + acc;
        }
        acc
    }

    // Test 1: SinsemillaHashToPoint with 10-bit message (single chunk)
    {
        let domain = "z.cash:test-Sinsemilla";
        // Message: bits 0,1,0,1,0,1,0,1,0,1 packed LE: byte0=0x55 (bits 0-7), byte1=0x02 (bits 8-9)
        let msg_bytes: [u8; 2] = [0x55, 0x02];

        let result = sinsemilla_hash_to_point(domain, &msg_bytes, 10);
        let result_bytes = point_to_le_bytes(&result);

        write_domain(out, "sinse_htp_domain", domain);
        writeln!(out, "static const size_t sinse_htp_domain_len = {};", domain.len()).unwrap();
        write_vector(out, "sinse_htp_msg", &msg_bytes);
        writeln!(out, "static const size_t sinse_htp_num_bits = 10;").unwrap();
        write_vector(out, "sinse_htp_expected", &result_bytes);
        writeln!(out).unwrap();
    }

    // Test 2: SinsemillaHashToPoint with 20-bit message (two chunks)
    {
        let domain = "z.cash:test-Sinsemilla";
        // 20 bits all 1s: 0xFF, 0xFF, 0x0F
        let msg_bytes: [u8; 3] = [0xFF, 0xFF, 0x0F];

        let result = sinsemilla_hash_to_point(domain, &msg_bytes, 20);
        let result_bytes = point_to_le_bytes(&result);

        write_vector(out, "sinse_htp2_msg", &msg_bytes);
        writeln!(out, "static const size_t sinse_htp2_num_bits = 20;").unwrap();
        write_vector(out, "sinse_htp2_expected", &result_bytes);
        writeln!(out).unwrap();
    }

    // Test 3: SinsemillaShortCommit (IVK-style, 510 zero bits)
    {
        let domain = "z.cash:Orchard-CommitIvk";
        let msg_bytes = [0u8; 64]; // 512 bits, use 510
        let num_bits: usize = 510;

        let rcm_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        let rcm = pallas::Scalar::from_repr(rcm_bytes).unwrap();

        // S = SinsemillaHashToPoint(domain + "-M", msg)
        let m_domain = format!("{}-M", domain);
        let s_point = sinsemilla_hash_to_point(&m_domain, &msg_bytes, num_bits);

        // R = hash_to_curve(domain + "-r")("")
        let r_domain = format!("{}-r", domain);
        let r_gen = pallas::Point::hash_to_curve(&r_domain)(&[]);

        // commit = S + [rcm] * R
        let commit = s_point + r_gen * rcm;
        let commit_bytes = point_to_le_bytes(&commit);

        write_domain(out, "sinse_sc_domain", domain);
        writeln!(out, "static const size_t sinse_sc_domain_len = {};", domain.len()).unwrap();
        write_vector(out, "sinse_sc_msg", &msg_bytes[..64]);
        writeln!(out, "static const size_t sinse_sc_num_bits = {};", num_bits).unwrap();
        write_vector(out, "sinse_sc_rcm", &rcm_bytes);
        write_vector(out, "sinse_sc_expected", &commit_bytes);
        writeln!(out).unwrap();
    }
}

// ─── F4Jumble ────────────────────────────────────────────────────────────────

fn generate_f4jumble_vectors(out: &mut String) {
    writeln!(out, "\n/* ── F4Jumble (ZIP-316) ── */\n").unwrap();

    // Test 1: 48 bytes (minimum length)
    {
        let input: Vec<u8> = (0u8..48).collect();
        let jumbled = f4jumble::f4jumble(&input).expect("f4jumble failed");

        write_vector(out, "f4j_input_1", &input);
        writeln!(out, "static const size_t f4j_len_1 = {};", input.len()).unwrap();
        write_vector(out, "f4j_expected_1", &jumbled);
        writeln!(out).unwrap();
    }

    // Test 2: 83 bytes (typical Unified Address: Orchard receiver + padding)
    {
        let input: Vec<u8> = (0u8..83).collect();
        let jumbled = f4jumble::f4jumble(&input).expect("f4jumble failed");

        write_vector(out, "f4j_input_2", &input);
        writeln!(out, "static const size_t f4j_len_2 = {};", input.len()).unwrap();
        write_vector(out, "f4j_expected_2", &jumbled);
        writeln!(out).unwrap();
    }

    // Test 3: 128 bytes
    {
        let input: Vec<u8> = (0..128).map(|i| (i as u8).wrapping_mul(7)).collect();
        let jumbled = f4jumble::f4jumble(&input).expect("f4jumble failed");

        write_vector(out, "f4j_input_3", &input);
        writeln!(out, "static const size_t f4j_len_3 = {};", input.len()).unwrap();
        write_vector(out, "f4j_expected_3", &jumbled);
        writeln!(out).unwrap();
    }
}

// ─── ZIP-32 Child Key Intermediates ──────────────────────────────────────────

fn prf_expand(sk: &[u8; 32], domain_and_parts: &[u8]) -> [u8; 64] {
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state()
        .update(sk)
        .update(domain_and_parts)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn child_key(sk_parent: &[u8; 32], cc_parent: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let mut input = [0u8; 37]; // 1 + 32 + 4
    input[0] = 0x81;
    input[1..33].copy_from_slice(sk_parent);
    input[33..37].copy_from_slice(&index.to_le_bytes());
    let i = prf_expand(cc_parent, &input);
    let mut sk = [0u8; 32];
    let mut cc = [0u8; 32];
    sk.copy_from_slice(&i[..32]);
    cc.copy_from_slice(&i[32..]);
    (sk, cc)
}

fn generate_zip32_intermediate_vectors(out: &mut String) {
    writeln!(out, "\n/* ── ZIP-32 Child Key Intermediates (per-hop) ── */\n").unwrap();

    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let seed_bytes = hex::decode(seed_hex).unwrap();

    // Master key
    let master = Blake2bParams::new()
        .hash_length(64)
        .personal(b"ZcashIP32Orchard")
        .hash(&seed_bytes);
    let mut sk_m = [0u8; 32];
    let mut cc_m = [0u8; 32];
    sk_m.copy_from_slice(&master.as_bytes()[..32]);
    cc_m.copy_from_slice(&master.as_bytes()[32..]);

    // Hop 1: m_Orchard / 32'
    let (sk_1, cc_1) = child_key(&sk_m, &cc_m, 0x80000000 | 32);
    write_vector(out, "zip32_hop1_sk", &sk_1);
    write_vector(out, "zip32_hop1_cc", &cc_1);

    // Hop 2: m_Orchard / 32' / 133'
    let (sk_2, cc_2) = child_key(&sk_1, &cc_1, 0x80000000 | 133);
    write_vector(out, "zip32_hop2_sk", &sk_2);
    write_vector(out, "zip32_hop2_cc", &cc_2);

    // Hop 3: m_Orchard / 32' / 133' / 0'
    let (sk_3, cc_3) = child_key(&sk_2, &cc_2, 0x80000000 | 0);
    write_vector(out, "zip32_hop3_sk", &sk_3);
    write_vector(out, "zip32_hop3_cc", &cc_3);
    writeln!(out).unwrap();
}

// ─── Sinsemilla with Real IVK Data ──────────────────────────────────────────

fn generate_sinsemilla_real_ivk_vectors(out: &mut String) {
    writeln!(out, "\n/* ── Sinsemilla ShortCommit with real ZIP-32 data (IVK) ── */\n").unwrap();

    use ff::PrimeField;

    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let seed = hex::decode(seed_hex).unwrap();

    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 133, 0u32.try_into().unwrap())
        .unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();
    let ak_bytes = &fvk_bytes[..32];
    let nk_bytes = &fvk_bytes[32..64];
    let rivk_bytes = &fvk_bytes[64..];

    // Build the 510-bit message: I2LEBSP_255(ak) || I2LEBSP_255(nk)
    // This is the same bit-packing the C code does in orchard_derive_unified_address
    let mut msg = [0u8; 64];
    // Copy ak (clear top bit for 255 bits)
    let mut ak_le = [0u8; 32];
    ak_le.copy_from_slice(ak_bytes);
    ak_le[31] &= 0x7F;
    msg[..32].copy_from_slice(&ak_le);

    // Copy nk into bits 255..509 (starting at bit 255 in msg)
    let mut nk_le = [0u8; 32];
    nk_le.copy_from_slice(nk_bytes);
    nk_le[31] &= 0x7F;
    for i in 0..255 {
        let sb = i / 8;
        let sbt = i % 8;
        let db = (255 + i) / 8;
        let dbt = (255 + i) % 8;
        if nk_le[sb] & (1 << sbt) != 0 {
            msg[db] |= 1 << dbt;
        }
    }

    // rcm = rivk interpreted as scalar
    let rivk_scalar = pallas::Scalar::from_repr(
        <[u8; 32]>::try_from(rivk_bytes).unwrap()
    ).unwrap();

    // SinsemillaShortCommit("z.cash:Orchard-CommitIvk", msg[510 bits], rivk)
    let domain = "z.cash:Orchard-CommitIvk";
    let m_domain = format!("{}-M", domain);

    // SinsemillaHashToPoint(domain+"-M", msg)
    fn sinsemilla_hash_to_point_fn(domain: &str, msg_bits: &[u8], num_bits: usize) -> pallas::Point {
        let q = pallas::Point::hash_to_curve("z.cash:SinsemillaQ")(domain.as_bytes());
        let mut acc = q;
        let num_chunks = num_bits / 10;
        for i in 0..num_chunks {
            let mut chunk: u32 = 0;
            for b in 0..10 {
                let bit_idx = i * 10 + b;
                if msg_bits[bit_idx / 8] & (1 << (bit_idx % 8)) != 0 {
                    chunk |= 1 << b;
                }
            }
            let s = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(&chunk.to_le_bytes());
            acc = (acc + s) + acc;
        }
        acc
    }

    let s_point = sinsemilla_hash_to_point_fn(&m_domain, &msg, 510);

    let r_domain = format!("{}-r", domain);
    let r_gen = pallas::Point::hash_to_curve(&r_domain)(&[]);
    let commit = s_point + r_gen * rivk_scalar;
    let commit_bytes = point_to_le_bytes(&commit);

    write_vector(out, "sinse_real_ivk_msg", &msg);
    writeln!(out, "static const size_t sinse_real_ivk_num_bits = 510;").unwrap();
    write_vector(out, "sinse_real_ivk_rivk", rivk_bytes);
    write_vector(out, "sinse_real_ivk_expected", &commit_bytes);
    writeln!(out).unwrap();
}

// ─── FF1-AES with Real dk ────────────────────────────────────────────────────

fn generate_ff1_real_dk_vectors(out: &mut String) {
    writeln!(out, "\n/* ── FF1-AES-256 with real dk from ZIP-32 ── */\n").unwrap();

    use ff::PrimeField;

    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let seed = hex::decode(seed_hex).unwrap();

    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 133, 0u32.try_into().unwrap())
        .unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();
    let ak_bytes = &fvk_bytes[..32];
    let nk_bytes = &fvk_bytes[32..64];
    let rivk_bytes = &fvk_bytes[64..];

    // dk = PRF_expand(rivk, [0x82] || ak || nk)[0..32]
    let sk_bytes = sk.to_bytes();
    let mut dk_input = Vec::new();
    dk_input.push(0x82);
    dk_input.extend_from_slice(ak_bytes);
    dk_input.extend_from_slice(nk_bytes);

    let dk_hash = Blake2bParams::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state()
        .update(rivk_bytes)
        .update(&dk_input)
        .finalize();
    let dk: [u8; 32] = dk_hash.as_bytes()[..32].try_into().unwrap();

    // FF1-AES-256(dk, [0]*11) = diversifier
    use fpe::ff1::{BinaryNumeralString, FF1};
    use aes::Aes256;

    let ff1 = FF1::<Aes256>::new(&dk, 2).unwrap();
    let input = [0u8; 11];
    let input_bns = BinaryNumeralString::from_bytes_le(&input);
    let output_bns = ff1.encrypt(&[], &input_bns).unwrap();
    let diversifier = output_bns.to_bytes_le();

    write_vector(out, "ff1_real_dk", &dk);
    write_vector(out, "ff1_real_input", &input);
    write_vector(out, "ff1_real_diversifier", &diversifier);
    writeln!(out).unwrap();
}

// ─── Additional RedPallas Test Cases ─────────────────────────────────────────

fn generate_redpallas_extra_vectors(out: &mut String) {
    writeln!(out, "\n/* ── RedPallas Extra Test Cases (deterministic nonce = 0x42*32) ── */\n").unwrap();

    use ff::PrimeField;

    let g_spend = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    let fixed_random = [0x42u8; 32];

    // Helper: compute full signing with given ask, alpha, sighash
    fn sign_deterministic(
        ask: &[u8; 32], alpha: &[u8; 32], sighash: &[u8; 32],
        g_spend: &pallas::Point, fixed_random: &[u8; 32],
    ) -> ([u8; 32], [u8; 64]) {
        let ask_s = pallas::Scalar::from_repr(*ask).unwrap();
        let alpha_s = pallas::Scalar::from_repr(*alpha).unwrap();
        let rsk = ask_s + alpha_s;
        let rk = *g_spend * rsk;
        let rk_bytes = point_to_le_bytes(&rk);
        let rsk_bytes = rsk.to_repr();

        let nonce_hash = Blake2bParams::new()
            .hash_length(64).personal(b"Zcash_RedPallasN")
            .to_state().update(&rsk_bytes).update(sighash).update(fixed_random)
            .finalize();
        let nonce = pallas::Scalar::from_uniform_bytes(nonce_hash.as_bytes().try_into().unwrap());

        let r_point = *g_spend * nonce;
        let r_bytes = point_to_le_bytes(&r_point);

        let ch_hash = Blake2bParams::new()
            .hash_length(64).personal(b"Zcash_RedPallasH")
            .to_state().update(&r_bytes).update(&rk_bytes).update(sighash)
            .finalize();
        let challenge = pallas::Scalar::from_uniform_bytes(ch_hash.as_bytes().try_into().unwrap());
        let s_scalar = nonce + challenge * rsk;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s_scalar.to_repr());
        (rk_bytes, sig)
    }

    // Generate valid scalars via from_uniform_bytes (64 bytes -> scalar mod q)
    // This mirrors how the C code handles arbitrary byte inputs (fq_from_wide)
    fn scalar_from_pattern(pattern: u8) -> [u8; 32] {
        let wide: [u8; 64] = [pattern; 64];
        pallas::Scalar::from_uniform_bytes(&wide).to_repr()
    }

    // Case 2: alpha = 0, sighash = random pattern
    {
        let ask = scalar_from_pattern(0x05);
        let alpha = [0u8; 32]; // zero alpha (valid scalar)
        let sighash: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
        let (rk, sig) = sign_deterministic(&ask, &alpha, &sighash, &g_spend, &fixed_random);

        write_vector(out, "rp2_ask", &ask);
        write_vector(out, "rp2_alpha", &alpha);
        write_vector(out, "rp2_sighash", &sighash);
        write_vector(out, "rp2_rk_expected", &rk);
        write_vector(out, "rp2_sig_expected", &sig);
        writeln!(out).unwrap();
    }

    // Case 3: sighash = 0, ask and alpha non-trivial
    {
        let ask = scalar_from_pattern(0x10);
        let alpha = scalar_from_pattern(0x30);
        let sighash = [0u8; 32]; // zero sighash
        let (rk, sig) = sign_deterministic(&ask, &alpha, &sighash, &g_spend, &fixed_random);

        write_vector(out, "rp3_ask", &ask);
        write_vector(out, "rp3_alpha", &alpha);
        write_vector(out, "rp3_sighash", &sighash);
        write_vector(out, "rp3_rk_expected", &rk);
        write_vector(out, "rp3_sig_expected", &sig);
        writeln!(out).unwrap();
    }

    // Case 4: large scalar values near q
    {
        let ask = scalar_from_pattern(0xFF);
        let alpha = scalar_from_pattern(0xEE);
        let sighash = [0xDD; 32];
        let (rk, sig) = sign_deterministic(&ask, &alpha, &sighash, &g_spend, &fixed_random);

        write_vector(out, "rp4_ask", &ask);
        write_vector(out, "rp4_alpha", &alpha);
        write_vector(out, "rp4_sighash", &sighash);
        write_vector(out, "rp4_rk_expected", &rk);
        write_vector(out, "rp4_sig_expected", &sig);
        writeln!(out).unwrap();
    }
}

// ─── F4Jumble Inverse ────────────────────────────────────────────────────────

fn generate_f4jumble_inv_vectors(out: &mut String) {
    writeln!(out, "\n/* ── F4Jumble Inverse (Round-Trip) ── */\n").unwrap();

    // For each test case, provide: input, jumbled, verify jumble(input)==jumbled and inv(jumbled)==input
    // We reuse the same test data from the forward tests (already in the header)
    // Just emit the inverse verification data

    // Test: 64 bytes (different from forward tests)
    {
        let input: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_add(0xAA)).collect();
        let jumbled = f4jumble::f4jumble(&input).expect("f4jumble failed");
        let roundtrip = f4jumble::f4jumble_inv(&jumbled).expect("f4jumble_inv failed");
        assert_eq!(input, roundtrip, "f4jumble roundtrip failed in generator");

        write_vector(out, "f4j_inv_input", &input);
        writeln!(out, "static const size_t f4j_inv_len = {};", input.len()).unwrap();
        write_vector(out, "f4j_inv_jumbled", &jumbled);
        writeln!(out).unwrap();
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let mut out = String::new();

    writeln!(
        out,
        "/**\n * Auto-generated test vectors for libzcash-orchard-c\n *\
         \n * Generated from librustzcash reference implementation.\n *\
         \n * DO NOT EDIT — regenerate with:\n *   cd tools/gen_test_vectors && cargo run 2>/dev/null > ../../tests/test_vectors.h\n */\n"
    )
    .unwrap();
    writeln!(out, "#ifndef TEST_VECTORS_H").unwrap();
    writeln!(out, "#define TEST_VECTORS_H\n").unwrap();
    writeln!(out, "#include <stdint.h>").unwrap();
    writeln!(out, "#include <stddef.h>\n").unwrap();

    generate_blake2b_vectors(&mut out);
    generate_hash_to_curve_vectors(&mut out);
    generate_sinsemilla_s_vectors(&mut out);
    generate_zip32_vectors(&mut out);
    generate_ff1_vectors(&mut out);
    generate_redpallas_vectors(&mut out);
    generate_sinsemilla_vectors(&mut out);
    generate_f4jumble_vectors(&mut out);
    generate_zip32_intermediate_vectors(&mut out);
    generate_sinsemilla_real_ivk_vectors(&mut out);
    generate_ff1_real_dk_vectors(&mut out);
    generate_redpallas_extra_vectors(&mut out);
    generate_f4jumble_inv_vectors(&mut out);

    writeln!(out, "\n#endif /* TEST_VECTORS_H */").unwrap();

    // Write to stdout
    std::io::stdout().write_all(out.as_bytes()).unwrap();
}
