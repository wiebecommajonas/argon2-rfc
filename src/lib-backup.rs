#![allow(clippy::many_single_char_names)]
mod utils;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2b, Digest, VarBlake2b,
};
use byteorder::{ByteOrder, LittleEndian};
use int_conv::Truncate;
use std::{num::Wrapping, slice::from_raw_parts_mut};
use utils::{le32, le64, xor};

#[derive(Copy, Clone, PartialEq)]
pub enum Argon2Type {
    Argon2d,
    Argon2i,
    Argon2id,
}

const SL: u32 = 4;

fn h_prime(tag_length: u32, input: &[u8]) -> Vec<u8> {
    if tag_length <= 64 {
        let mut var_hasher = VarBlake2b::new(tag_length as usize).unwrap();
        var_hasher.update(&le32(tag_length));
        var_hasher.update(input);
        let mut result = Vec::new();
        var_hasher.finalize_variable(|res| result.extend_from_slice(res));
        result
    } else {
        let mut hasher = Blake2b::new();
        Digest::update(&mut hasher, &le32(tag_length));
        Digest::update(&mut hasher, input);
        let r = ((32 + tag_length - 1) / 32) - 2;
        let mut result = Vec::new();

        result.extend_from_slice(&hasher.finalize_reset().as_slice()[..32]);
        for _ in 1..r {
            Digest::update(&mut hasher, &result[(result.len() - 32)..]);
            result.extend_from_slice(&hasher.finalize_reset().as_slice()[..32])
        }
        let mut var_hasher = VarBlake2b::new((tag_length - 32 * r) as usize).unwrap();
        var_hasher.update(&result[(result.len() - 32)..]);
        var_hasher.finalize_variable(|res| result.extend_from_slice(res));
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn h0(
    password: &[u8],
    salt: &[u8],
    degree_of_parallelism: u32,
    tag_length: u32,
    memory_size: u32,
    number_of_passes: u32,
    version_number: u8,
    secret_value: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    argon2_type: Argon2Type,
) -> [u8; 64] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&le32(degree_of_parallelism));
    bytes.extend_from_slice(&le32(tag_length));
    bytes.extend_from_slice(&le32(memory_size));
    bytes.extend_from_slice(&le32(number_of_passes));
    bytes.extend_from_slice(&le32(version_number));
    bytes.extend_from_slice(&le32(argon2_type as u32));
    bytes.extend_from_slice(&le32(password.len() as u32));
    bytes.extend_from_slice(password);
    if salt.is_empty() {
        bytes.extend_from_slice(&le32(0_u32));
    } else {
        bytes.extend_from_slice(&le32(salt.len() as u32));
        bytes.extend_from_slice(salt);
    }
    if let Some(secret) = secret_value {
        if secret.is_empty() {
            bytes.extend_from_slice(&le32(0_u32));
        } else {
            bytes.extend_from_slice(&le32(secret.len() as u32));
            bytes.extend_from_slice(secret);
        }
    } else {
        bytes.extend_from_slice(&le32(0_u32));
    }
    if let Some(associated) = associated_data {
        if associated.is_empty() {
            bytes.extend_from_slice(&le32(0_u32));
        } else {
            bytes.extend_from_slice(&le32(associated.len() as u32));
            bytes.extend_from_slice(associated);
        }
    } else {
        bytes.extend_from_slice(&le32(0_u32));
    }

    let mut h0 = [0u8; 64];
    let mut hasher = Blake2b::new();
    Digest::update(&mut hasher, &bytes);
    h0.copy_from_slice(&hasher.finalize());
    h0
}

fn g(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), 1024, "x needs to be 1024 bytes");
    assert_eq!(y.len(), 1024, "y needs to be 1024 bytes");

    let r: Vec<u8> = x.iter().zip(y.iter()).map(|(&x_, &y_)| x_ ^ y_).collect();
    let mut q = r.clone();
    q.chunks_exact_mut(128).for_each(|r_| p(r_));
    let mut z = utils::transpose(&q.clone(), 8_usize, 128_usize);
    z.chunks_exact_mut(128).for_each(|q_| p(q_));
    z = utils::transpose(&z, 8_usize, 128_usize);

    z.iter()
        .zip(r.iter())
        .map(|(z_, r_)| z_ ^ r_)
        .collect::<Vec<u8>>()
}

fn p(input: &mut [u8]) {
    // println!("P input:\n{:?}", input);
    assert_eq!(input.len(), 128, "input needs to be 8 16 byte chunks");

    let v = (0_usize..16)
        .map(|i| [16 * i + 8, 16 * i])
        .flatten()
        .collect::<Vec<usize>>();

    let ptr = input.as_mut_ptr();
    unsafe {
        let v_0 = from_raw_parts_mut(ptr.add(v[0]), 8);
        let v_1 = from_raw_parts_mut(ptr.add(v[1]), 8);
        let v_2 = from_raw_parts_mut(ptr.add(v[2]), 8);
        let v_3 = from_raw_parts_mut(ptr.add(v[3]), 8);
        let v_4 = from_raw_parts_mut(ptr.add(v[4]), 8);
        let v_5 = from_raw_parts_mut(ptr.add(v[5]), 8);
        let v_6 = from_raw_parts_mut(ptr.add(v[6]), 8);
        let v_7 = from_raw_parts_mut(ptr.add(v[7]), 8);
        let v_8 = from_raw_parts_mut(ptr.add(v[8]), 8);
        let v_9 = from_raw_parts_mut(ptr.add(v[9]), 8);
        let v_10 = from_raw_parts_mut(ptr.add(v[10]), 8);
        let v_11 = from_raw_parts_mut(ptr.add(v[11]), 8);
        let v_12 = from_raw_parts_mut(ptr.add(v[12]), 8);
        let v_13 = from_raw_parts_mut(ptr.add(v[13]), 8);
        let v_14 = from_raw_parts_mut(ptr.add(v[14]), 8);
        let v_15 = from_raw_parts_mut(ptr.add(v[15]), 8);

        gb(v_0, v_4, v_8, v_12);
        gb(v_1, v_5, v_9, v_13);
        gb(v_2, v_6, v_10, v_14);
        gb(v_3, v_7, v_11, v_15);

        gb(v_0, v_5, v_10, v_15);
        gb(v_1, v_6, v_11, v_12);
        gb(v_2, v_7, v_8, v_13);
        gb(v_3, v_4, v_9, v_14);
    }

    // println!("P result:\n{:?}", input);
}

fn gb(a_: &mut [u8], b_: &mut [u8], c_: &mut [u8], d_: &mut [u8]) {
    // println!("GB input:\n{:?}\n{:?}\n{:?}\n{:?}", a_, b_, c_, d_);
    assert!(
        a_.len() == 8 && b_.len() == 8 && c_.len() == 8 && d_.len() == 8,
        "input needs to be 4 8 byte chunks"
    );

    let mut a = LittleEndian::read_u64(a_);
    let mut b = LittleEndian::read_u64(b_);
    let mut c = LittleEndian::read_u64(c_);
    let mut d = LittleEndian::read_u64(d_);

    a = (Wrapping(a)
        + Wrapping(b)
        + Wrapping(2)
            * Wrapping(Truncate::<u32>::truncate(a) as u64)
            * Wrapping(Truncate::<u32>::truncate(b) as u64))
    .0;
    d = (d ^ a).rotate_right(32);
    c = (Wrapping(c)
        + Wrapping(d)
        + Wrapping(2)
            * Wrapping(Truncate::<u32>::truncate(c) as u64)
            * Wrapping(Truncate::<u32>::truncate(d) as u64))
    .0;
    b = (b ^ c).rotate_right(24);

    a = (Wrapping(a)
        + Wrapping(b)
        + Wrapping(2)
            * Wrapping(Truncate::<u32>::truncate(a) as u64)
            * Wrapping(Truncate::<u32>::truncate(b) as u64))
    .0;
    d = (d ^ a).rotate_right(16);
    c = (Wrapping(c)
        + Wrapping(d)
        + Wrapping(2)
            * Wrapping(Truncate::<u32>::truncate(c) as u64)
            * Wrapping(Truncate::<u32>::truncate(d) as u64))
    .0;
    b = (b ^ c).rotate_right(63);

    LittleEndian::write_u64(a_, a);
    LittleEndian::write_u64(b_, b);
    LittleEndian::write_u64(c_, c);
    LittleEndian::write_u64(d_, d);
}

#[allow(clippy::too_many_arguments)]
pub fn argon2(
    password: &[u8],
    salt: &[u8],
    degree_of_parallelism: u32,
    tag_length: u32,
    memory_size: u32,
    number_of_passes: u32,
    version_number: u8,
    secret_value: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    argon2_type: Argon2Type,
) {
    assert!(password.len() < u32::MAX as usize, "Password is too long");
    assert!(salt.len() < u32::MAX as usize, "Salt is too long");
    assert!(
        (1..=16777215).contains(&degree_of_parallelism),
        "Degree of parralellism invalid"
    );
    assert!(tag_length >= 4, "Tag length invalid");
    assert!(
        memory_size >= 8 * degree_of_parallelism,
        "Memory size invalid"
    );
    assert!(number_of_passes >= 1, "Number of passes invalid");
    if let Some(secret) = secret_value {
        assert!(secret.len() <= u32::MAX as usize, "Secret is too long");
    }
    if let Some(associated) = associated_data {
        assert!(
            associated.len() <= u32::MAX as usize,
            "Associated data is too long"
        );
    }

    let _h0 = h0(
        password,
        salt,
        degree_of_parallelism,
        tag_length,
        memory_size,
        number_of_passes,
        version_number,
        secret_value,
        associated_data,
        argon2_type,
    );

    let m_prime = 4 * degree_of_parallelism * (memory_size / (4 * degree_of_parallelism));
    let mut b = vec![0; m_prime as usize * 1024];
    let q = m_prime / degree_of_parallelism;

    dbg!(m_prime, q);

    for i in 0..degree_of_parallelism {
        let mut bi0 = Vec::new();
        bi0.extend_from_slice(&_h0);
        let mut bi1 = bi0.clone();
        bi0.extend_from_slice(&le32(0_u32));
        bi0.extend_from_slice(&le32(i));
        bi1.extend_from_slice(&le32(1_u32));
        bi1.extend_from_slice(&le32(i));
        let index0 = i as usize * q as usize * 1024;
        let index1 = i as usize * q as usize * 1024 + 1024;
        b.splice(index0..index0 + 1024, h_prime(1024, &bi0));
        b.splice(index1..index1 + 1024, h_prime(1024, &bi1));
    }

    let pass = 0u32;

    for slice in 1..SL {
        for lane in 0..degree_of_parallelism {
            for sl_block in 0..(q / SL) {
                let j = slice * q / SL + sl_block;
                let index = lane as usize * q as usize * 1024 + j as usize * 1024;
                let index_prev = index - 1024;
                let j_1: u32;
                let j_2: u32;
                if argon2_type == Argon2Type::Argon2d
                    || (argon2_type == Argon2Type::Argon2id
                        && pass == 0
                        && (lane == 0 || lane == 1))
                {
                    j_1 = LittleEndian::read_u32(&b[index_prev as usize..index_prev as usize + 32]);
                    j_2 = LittleEndian::read_u32(
                        &b[index_prev as usize + 32..index_prev as usize + 64],
                    );
                } else {
                    let mut z = Vec::new();
                    z.extend_from_slice(&le64(pass));
                    z.extend_from_slice(&le64(lane));
                    z.extend_from_slice(&le64(slice));
                    z.extend_from_slice(&le64(m_prime));
                    z.extend_from_slice(&le64(number_of_passes));
                    z.extend_from_slice(&le64(argon2_type as u64));

                    let mut x = Vec::new();
                    for i in 1..=((q * 1024) / (128 * 4)) {
                        let mut a = Vec::new();
                        a.extend_from_slice(&z);
                        a.extend_from_slice(&le64(i));
                        a.extend_from_slice(&[0; 968]);
                        x.extend_from_slice(&g(&[0; 1024], &g(&[0; 1024], &a)));
                    }
                    j_1 = LittleEndian::read_u32(&x[..32]);
                    let half = q as usize * 1024 / 2;
                    j_2 = LittleEndian::read_u32(&x[half..half + 32]);
                }
                let l = if slice == 0 || pass == 0 {
                    lane
                } else {
                    j_2 % degree_of_parallelism
                };
                let mut w = Vec::new();
                if l == lane {
                    w.extend_from_slice(&(0..j as usize - 1).collect::<Vec<usize>>());
                } else {
                    w.extend_from_slice(&(0..(slice * q / SL) as usize).collect::<Vec<usize>>());
                    if j % (q / SL) == 0 {
                        w.remove(w.len() - 1);
                    }
                }

                let z = {
                    let x = (j_1 as u64 * j_1 as u64) >> 32;
                    let y = (w.len() as u64 * x) >> 32;
                    let zz = w.len() - 1 - y as usize;
                    w[zz]
                };

                let index_comp = l as usize * 4 * 1024 + z * 1024;
                b.splice(
                    index..index + 1024,
                    g(&b[index_prev..index], &b[index_comp..index_comp + 1024]),
                );
            }
        }
    }

    println!("After pass 0 (first bytes of block 0):\n{:?}", &b[..8]);
    // println!("After pass 0 (first bytes of block 0):\n{:?}", &b[..8]);

    for pass in 1..number_of_passes {
        dbg!(pass);
        for slice in 0..SL {
            for lane in 0..degree_of_parallelism {
                for sl_block in 0..(q / SL) {
                    if slice == 0 && sl_block == 0 {
                        continue;
                    }
                    let j = slice * q / SL + sl_block;
                    let index = lane as usize * q as usize * 1024 + j as usize * 1024;
                    let index_prev = index - 1024;
                    let j_1: u32;
                    let j_2: u32;
                    if argon2_type == Argon2Type::Argon2d
                        || (argon2_type == Argon2Type::Argon2id
                            && pass == 0
                            && (lane == 0 || lane == 1))
                    {
                        j_1 = LittleEndian::read_u32(
                            &b[index_prev as usize..index_prev as usize + 32],
                        );
                        j_2 = LittleEndian::read_u32(
                            &b[index_prev as usize + 32..index_prev as usize + 64],
                        );
                    } else {
                        let mut z = Vec::new();
                        z.extend_from_slice(&le64(pass));
                        z.extend_from_slice(&le64(lane));
                        z.extend_from_slice(&le64(slice));
                        z.extend_from_slice(&le64(m_prime));
                        z.extend_from_slice(&le64(number_of_passes));
                        z.extend_from_slice(&le64(argon2_type as u64));

                        let mut x = Vec::new();
                        for i in 1..=((q * 1024) / (128 * 4)) {
                            let mut a = Vec::new();
                            a.extend_from_slice(&z);
                            a.extend_from_slice(&le64(i));
                            a.extend_from_slice(&[0; 968]);
                            x.extend_from_slice(&g(&[0; 1024], &g(&[0; 1024], &a)));
                        }
                        j_1 = LittleEndian::read_u32(&x[..32]);
                        let half = q as usize * 1024 / 2;
                        j_2 = LittleEndian::read_u32(&x[half..half + 32]);
                    }
                    let l = if slice == 0 || pass == 0 {
                        lane
                    } else {
                        j_2 % degree_of_parallelism
                    };
                    let mut w = Vec::new();
                    if l == lane {
                        w.extend_from_slice(&(0..j as usize - 1).collect::<Vec<usize>>());
                        if slice < 3 {
                            w.extend_from_slice(
                                &((((slice + 1) % SL) * q / SL) as usize..(SL * q / SL) as usize)
                                    .collect::<Vec<usize>>(),
                            );
                        }
                    } else {
                        w.extend_from_slice(
                            &(0..(slice * q / SL) as usize).collect::<Vec<usize>>(),
                        );
                        if slice < 3 {
                            w.extend_from_slice(
                                &((((slice + 1) % SL) * q / SL) as usize..(SL * q / SL) as usize)
                                    .collect::<Vec<usize>>(),
                            );
                        }
                        if j % (q / SL) == 0 {
                            w.remove(w.len() - 1);
                        }
                    }

                    let z = {
                        let x = (j_1 as u64 * j_1 as u64) >> 32;
                        let y = (w.len() as u64 * x) >> 32;
                        let zz = w.len() - 1 - y as usize;
                        w[zz]
                    };

                    let index_comp = l as usize * 4 * 1024 + z * 1024;
                    let first_block = lane as usize * q as usize * 1024;
                    let last_block = lane as usize * q as usize * 1024 + (q as usize - 1) * 1024;
                    b.splice(
                        first_block..first_block + 1024,
                        xor(
                            &g(
                                &b[last_block..last_block + 1024],
                                &b[index_comp..index_comp + 1024],
                            ),
                            &b[first_block..first_block + 1024],
                        ),
                    );
                    b.splice(
                        index..index + 1024,
                        xor(
                            &g(&b[index - 1024..index], &b[index_comp..index_comp + 1024]),
                            &b[index..index + 1024],
                        ),
                    );
                }
            }
        }
        println!(
            "After pass {} (first bytes of block 0):\n{:?}",
            pass,
            &b[..8]
        );
    }

    let mut c = Vec::new();
    let col = (q as usize - 1) * 1024;
    c.extend_from_slice(&b[col..col + 1024]);

    for lane in 1..degree_of_parallelism {
        let index = lane as usize * q as usize + col;
        c.splice(0..1024, xor(&c[0..1024], &b[index..index + 1024]));
    }

    let output_tag = h_prime(tag_length, &c);

    println!("output tag: {:?}", &output_tag);
    dbg!(&output_tag.len());
}

#[cfg(test)]
mod test {
    use crate::{argon2, h0, h_prime, p, Argon2Type};

    #[test]
    fn argon2id_rfc_test() {
        argon2(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            19,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Argon2Type::Argon2id,
        );
        println!("After pass 0 (first bytes of block 0) should be:\n{:?}", {
            let mut a = hex_literal::hex!("6b2e09f10671bd43");
            a.reverse();
            a
        });
        println!("After pass 1 (first bytes of block 0) should be:\n{:?}", {
            let mut a = hex_literal::hex!("3653ec9d01583df9");
            a.reverse();
            a
        });
        println!("After pass 2 (first bytes of block 0) should be:\n{:?}", {
            let mut a = hex_literal::hex!("942363968ce597a4");
            a.reverse();
            a
        });
        println!(
            "Output tag should be:\n{:?}",
            hex_literal::hex!(
                "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0
 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59"
            )
        );
    }

    #[test]
    fn h0_argon2id_rfc_test() {
        let _h0 = h0(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            19,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Argon2Type::Argon2id,
        );
        assert_eq!(
            _h0,
            hex_literal::hex!(
                "28 89 de 48 7e b4 2a e5 00 c0 00 7e d9 25 2f
 10 69 ea de c4 0d 57 65 b4 85 de 6d c2 43 7a 67 b8 54 6a 2f 0a
 cc 1a 08 82 db 8f cf 74 71 4b 47 2e 94 df 42 1a 5d a1 11 2f fa
 11 43 43 70 a1 e9 97"
            )
        )
    }

    #[test]
    fn h0_argon2d_rfc_test() {
        let _h0 = h0(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            19,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Argon2Type::Argon2d,
        );
        assert_eq!(
            _h0,
            hex_literal::hex!(
                "b8 81 97 91 a0 35 96 60
                    bb 77 09 c8 5f a4 8f 04
                    d5 d8 2c 05 c5 f2 15 cc
                    db 88 54 91 71 7c f7 57
                    08 2c 28 b9 51 be 38 14
                    10 b5 fc 2e b7 27 40 33
                    b9 fd c7 ae 67 2b ca ac
                    5d 17 90 97 a4 af 31 09"
            )
        )
    }

    #[test]
    fn h0_argon2i_rfc_test() {
        let _h0 = h0(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            19,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Argon2Type::Argon2i,
        );
        assert_eq!(
            _h0,
            hex_literal::hex!(
                "c4 60 65 81 52 76 a0 b3
                    e7 31 73 1c 90 2f 1f d8
                    0c f7 76 90 7f bb 7b 6a
                    5c a7 2e 7b 56 01 1f ee
                    ca 44 6c 86 dd 75 b9 46
                    9a 5e 68 79 de c4 b7 2d
                    08 63 fb 93 9b 98 2e 5f
                    39 7c c7 d1 64 fd da a9"
            )
        )
    }
}
