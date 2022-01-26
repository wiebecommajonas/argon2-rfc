#![allow(clippy::many_single_char_names)]
mod utils;

use std::{
    convert::TryInto,
    num::Wrapping,
    ops::Range,
    slice::{from_raw_parts, from_raw_parts_mut},
};
use utils::{le32, le64, xor};

#[derive(Copy, Clone, PartialEq)]
pub enum Variant {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

#[derive(Copy, Clone, PartialEq)]
pub enum Version {
    V0x10 = 0x10,
    V0x13 = 0x13,
}

pub struct Argon2 {
    password: Vec<u8>,
    salt: Vec<u8>,
    degree_of_parallelism: u32,
    tag_length: u32,
    memory_size: u32,
    number_of_passes: u32,
    version_number: Version,
    secret_value: Option<Vec<u8>>,
    associated_data: Option<Vec<u8>>,
    argon2_type: Variant,
    m_prime: u32,
    q: u32,
    blocks: Vec<u8>,
}

type BlockIndex = Range<usize>;

impl Argon2 {
    pub const SL: u32 = 4;
    pub const BLOCKSIZE: u32 = 1024;
    pub const INDEX_BITSHIFT: u32 = 10;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        password: &[u8],
        salt: &[u8],
        degree_of_parallelism: u32,
        tag_length: u32,
        memory_size: u32,
        number_of_passes: u32,
        version_number: Version,
        secret_value: Option<&[u8]>,
        associated_data: Option<&[u8]>,
        argon2_type: Variant,
    ) -> Self {
        debug_assert!(password.len() < u32::MAX as usize, "Password is too long");
        debug_assert!(salt.len() < u32::MAX as usize, "Salt is too long");
        debug_assert!(
            (1..=16777215).contains(&degree_of_parallelism),
            "Degree of parralellism invalid"
        );
        debug_assert!(tag_length >= 4, "Tag length invalid");
        debug_assert!(
            memory_size >= 8 * degree_of_parallelism,
            "Memory size invalid"
        );
        debug_assert!(number_of_passes >= 1, "Number of passes invalid");

        let mut s: Option<Vec<u8>> = None;
        let mut a: Option<Vec<u8>> = None;
        if let Some(secret) = secret_value {
            debug_assert!(secret.len() <= u32::MAX as usize, "Secret is too long");
            s = Some(secret.to_vec());
        }
        if let Some(associated) = associated_data {
            debug_assert!(
                associated.len() <= u32::MAX as usize,
                "Associated data is too long"
            );
            a = Some(associated.to_vec());
        }

        let m_prime = 4 * degree_of_parallelism * (memory_size / (4 * degree_of_parallelism));
        let blocks = vec![0; m_prime as usize * 1024];
        let q = m_prime / degree_of_parallelism;

        Self {
            password: password.to_vec(),
            salt: salt.to_vec(),
            degree_of_parallelism,
            tag_length,
            memory_size,
            number_of_passes,
            version_number,
            secret_value: s,
            associated_data: a,
            argon2_type,
            m_prime,
            q,
            blocks,
        }
    }

    #[inline(always)]
    pub(crate) fn block_index(block: u32) -> BlockIndex {
        let index = (block << Self::INDEX_BITSHIFT) as usize;
        index..index + Self::BLOCKSIZE as usize
    }

    #[inline(always)]
    pub(crate) fn partial_block_index(block: u32, from: usize, to: usize) -> BlockIndex {
        let index = (block << Self::INDEX_BITSHIFT) as usize;
        index + from..index + to
    }

    pub(crate) fn previous(&self, block: u32) -> u32 {
        let lane = block / self.q;
        let mut block_in_lane = block % self.q;
        if block_in_lane > 0 {
            block_in_lane -= 1;
        } else {
            block_in_lane = self.q - 1
        }

        lane * self.q + block_in_lane
    }

    pub fn get3(&mut self, a: u32, b: u32, c: u32) -> (&mut [u8], &[u8], &[u8]) {
        let mptr = self.blocks.as_mut_ptr();
        let ptr = self.blocks.as_ptr();
        unsafe {
            (
                from_raw_parts_mut(
                    mptr.add((a * Self::BLOCKSIZE) as usize),
                    Self::BLOCKSIZE as usize,
                ),
                from_raw_parts(
                    ptr.add((b * Self::BLOCKSIZE) as usize),
                    Self::BLOCKSIZE as usize,
                ),
                from_raw_parts(
                    ptr.add((c * Self::BLOCKSIZE) as usize),
                    Self::BLOCKSIZE as usize,
                ),
            )
        }
    }

    pub(crate) fn h_prime(dest: &mut [u8], input: &[u8]) {
        let len = dest.len();
        if len <= 64 {
            b2hash!(dest; &le32(len as u32), input);
        } else {
            let mut v_i = b2hash!(&le32(len as u32), input);
            dest[..32].copy_from_slice(&v_i[..32]);

            let mut i = 1usize;
            while len as usize - i * 32 > 64 {
                b2hash!(&mut v_i; &v_i);
                dest[i * 32..(i + 1) * 32].copy_from_slice(&v_i[..32]);
                i += 1;
            }

            let last_len = len as usize - i * 32;
            b2hash!(&mut dest[i*32..i*32 + last_len]; &v_i);
        }
    }

    pub(crate) fn h0(&self) -> [u8; 64] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&le32(self.degree_of_parallelism));
        bytes.extend_from_slice(&le32(self.tag_length));
        bytes.extend_from_slice(&le32(self.memory_size));
        bytes.extend_from_slice(&le32(self.number_of_passes));
        bytes.extend_from_slice(&le32(self.version_number as u32));
        bytes.extend_from_slice(&le32(self.argon2_type as u32));
        bytes.extend_from_slice(&le32(self.password.len() as u32));
        bytes.extend_from_slice(&self.password);
        if self.salt.is_empty() {
            bytes.extend_from_slice(&le32(0_u32));
        } else {
            bytes.extend_from_slice(&le32(self.salt.len() as u32));
            bytes.extend_from_slice(&self.salt);
        }
        if let Some(secret) = &self.secret_value {
            if secret.is_empty() {
                bytes.extend_from_slice(&le32(0_u32));
            } else {
                bytes.extend_from_slice(&le32(secret.len() as u32));
                bytes.extend_from_slice(secret);
            }
        } else {
            bytes.extend_from_slice(&le32(0_u32));
        }
        if let Some(associated) = &self.associated_data {
            if associated.is_empty() {
                bytes.extend_from_slice(&le32(0_u32));
            } else {
                bytes.extend_from_slice(&le32(associated.len() as u32));
                bytes.extend_from_slice(associated);
            }
        } else {
            bytes.extend_from_slice(&le32(0_u32));
        }

        b2hash!(&bytes)
    }

    pub(crate) fn transpose(block: &mut [u8], dims: usize) {
        let rowsize = Self::BLOCKSIZE as usize / dims;
        let slicelen = rowsize / dims;
        for row in 0..(dims - 1) {
            for col in (row + 1)..dims {
                unsafe {
                    let dest_ptr: *mut [u8] = &mut block
                        [col * rowsize + row * slicelen..col * rowsize + (row + 1) * slicelen];
                    let src_ptr: *mut [u8] = &mut block
                        [row * rowsize + col * slicelen..row * rowsize + (col + 1) * slicelen];
                    dest_ptr
                        .as_mut()
                        .unwrap()
                        .swap_with_slice(src_ptr.as_mut().unwrap());
                }
            }
        }
    }

    pub(crate) fn g(dest: &mut [u8], x: &[u8], y: &[u8]) {
        debug_assert_eq!(x.len(), 1024, "x needs to be 1024 bytes");
        debug_assert_eq!(y.len(), 1024, "y needs to be 1024 bytes");
        debug_assert_eq!(dest.len(), 1024, "dest needs to be 1024 bytes");

        const ROWSIZE: usize = 128;

        for (d_, (x_, y_)) in dest.iter_mut().zip(x.iter().zip(y.iter())) {
            *d_ = x_ ^ y_;
        }

        for row in 0..8 {
            Self::p(&mut dest[row * ROWSIZE..(row + 1) * ROWSIZE]);
        }

        Self::transpose(dest, 8);

        for row in 0..8 {
            Self::p(&mut dest[row * ROWSIZE..(row + 1) * ROWSIZE]);
        }

        Self::transpose(dest, 8);

        for (d_, (x_, y_)) in dest.iter_mut().zip(x.iter().zip(y.iter())) {
            *d_ = *d_ ^ x_ ^ y_;
        }
    }

    pub(crate) fn g_xor(dest: &mut [u8], x: &[u8], y: &[u8]) {
        debug_assert_eq!(x.len(), 1024, "x needs to be 1024 bytes");
        debug_assert_eq!(y.len(), 1024, "y needs to be 1024 bytes");
        debug_assert_eq!(dest.len(), 1024, "dest needs to be 1024 bytes");

        const ROWSIZE: usize = 128;

        let mut tmp = [0u8; 1024];
        let xy = x.iter().zip(y.iter());
        for ((d_, t), (x_, y_)) in dest.iter_mut().zip(tmp.iter_mut()).zip(xy) {
            *t = *x_ ^ *y_;
            *d_ ^= *t;
        }

        for row in 0..8 {
            Self::p(&mut tmp[row * ROWSIZE..(row + 1) * ROWSIZE]);
        }

        Self::transpose(&mut tmp, 8);

        for row in 0..8 {
            Self::p(&mut tmp[row * ROWSIZE..(row + 1) * ROWSIZE]);
        }

        Self::transpose(&mut tmp, 8);

        for (d_, t) in dest.iter_mut().zip(tmp) {
            *d_ ^= t;
        }
    }

    pub(crate) fn p(input: &mut [u8]) {
        debug_assert_eq!(input.len(), 128, "input needs to be 8 16 byte chunks");

        let v = (0..8)
            .flat_map(|i| [2 * i, 2 * i + 1])
            .collect::<Vec<usize>>();

        let ptr = input.as_mut_ptr();
        unsafe {
            let mut vs = [std::ptr::null_mut(); 16];
            for i in 0..16 {
                vs[i] = ptr.add(v[i] * 8);
            }

            Self::gb(vs[0], vs[4], vs[8], vs[12]);
            Self::gb(vs[1], vs[5], vs[9], vs[13]);
            Self::gb(vs[2], vs[6], vs[10], vs[14]);
            Self::gb(vs[3], vs[7], vs[11], vs[15]);

            Self::gb(vs[0], vs[5], vs[10], vs[15]);
            Self::gb(vs[1], vs[6], vs[11], vs[12]);
            Self::gb(vs[2], vs[7], vs[8], vs[13]);
            Self::gb(vs[3], vs[4], vs[9], vs[14]);
        }
    }

    pub(crate) unsafe fn gb(a_: *mut u8, b_: *mut u8, c_: *mut u8, d_: *mut u8) {
        let mut a = u64::from_le_bytes(from_raw_parts_mut(a_, 8).as_ref().try_into().unwrap());
        let mut b = u64::from_le_bytes(from_raw_parts_mut(b_, 8).as_ref().try_into().unwrap());
        let mut c = u64::from_le_bytes(from_raw_parts_mut(c_, 8).as_ref().try_into().unwrap());
        let mut d = u64::from_le_bytes(from_raw_parts_mut(d_, 8).as_ref().try_into().unwrap());

        a = (Wrapping(a)
            + Wrapping(b)
            + Wrapping(2) * Wrapping(utils::lo(a)) * Wrapping(utils::lo(b)))
        .0;
        d = (d ^ a).rotate_right(32);
        c = (Wrapping(c)
            + Wrapping(d)
            + Wrapping(2) * Wrapping(utils::lo(c)) * Wrapping(utils::lo(d)))
        .0;
        b = (b ^ c).rotate_right(24);

        a = (Wrapping(a)
            + Wrapping(b)
            + Wrapping(2) * Wrapping(utils::lo(a)) * Wrapping(utils::lo(b)))
        .0;
        d = (d ^ a).rotate_right(16);
        c = (Wrapping(c)
            + Wrapping(d)
            + Wrapping(2) * Wrapping(utils::lo(c)) * Wrapping(utils::lo(d)))
        .0;
        b = (b ^ c).rotate_right(63);

        a_.copy_from_nonoverlapping(a.to_le_bytes().as_ptr(), 8);
        b_.copy_from_nonoverlapping(b.to_le_bytes().as_ptr(), 8);
        c_.copy_from_nonoverlapping(c.to_le_bytes().as_ptr(), 8);
        d_.copy_from_nonoverlapping(d.to_le_bytes().as_ptr(), 8);
    }

    pub(crate) fn index_l_z(&self, pass: u32, block: u32) -> (u32, u32) {
        let lane = block / self.q;
        let block_in_lane = block % self.q;
        let segment_len = self.q / Self::SL;
        let slice = block_in_lane / segment_len;
        let sliceidx = block_in_lane % segment_len;
        let prev_block = self.previous(block);
        let prev_block_index_one = Self::partial_block_index(prev_block, 0, 4);
        let prev_block_index_two = Self::partial_block_index(prev_block, 4, 8);

        let mut j_1: u32 = 0;
        let mut j_2: u32 = 0;
        if self.argon2_type == Variant::Argon2d
            || (self.argon2_type == Variant::Argon2id && pass == 0 && (lane == 0 || lane == 1))
        {
            j_1 = u32::from_le_bytes(
                self.blocks[prev_block_index_one]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );
            j_2 = u32::from_le_bytes(
                self.blocks[prev_block_index_two]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );
        } else {
            let mut z = Vec::new();
            z.extend_from_slice(&le64(pass));
            z.extend_from_slice(&le64(lane));
            z.extend_from_slice(&le64(slice));
            z.extend_from_slice(&le64(self.m_prime));
            z.extend_from_slice(&le64(self.number_of_passes));
            z.extend_from_slice(&le64(self.argon2_type as u64));

            for i in 1..=(self.q / (128 * Self::SL)) {
                let mut x = Vec::new();
                let mut a = Vec::new();
                a.extend_from_slice(&z);
                a.extend_from_slice(&le64(i));
                a.extend_from_slice(&[0; 968]);
                /* x.extend_from_slice(&Self::g(&[0; 1024], &Self::g(&[0; 1024], &a))); */
                dbg!(x.len());
                dbg!(x.len() / (segment_len) as usize);
                let half = x.len() / 2;
                for _ in 0..segment_len {
                    j_1 = u32::from_le_bytes(x[..4].as_ref().try_into().unwrap());
                    j_2 = u32::from_le_bytes(x[half..half + 4].as_ref().try_into().unwrap());
                }
            }
        }
        let l = match (slice, pass) {
            (0, 0) => lane,
            _ => j_2 % self.degree_of_parallelism,
        };

        let w = match (pass, slice, j_2 % self.degree_of_parallelism == lane) {
            (0, 0, _) => sliceidx - 1,
            (0, _, false) => slice * segment_len - if sliceidx == 0 { 1 } else { 0 },
            (0, _, true) => slice * segment_len + sliceidx - 1,
            (_, _, false) => self.q - segment_len - if sliceidx == 0 { 1 } else { 0 },
            (_, _, true) => self.q - segment_len + sliceidx - 1,
        };

        let (w_, j1_) = (w as u64, j_1 as u64);
        let relpos = (w_ - 1 - (w_ * (j1_ * j1_ >> 32) >> 32)) as u32;

        let z = match (pass, slice) {
            (0, _) | (_, 3) => relpos % self.q,
            _ => (segment_len * (slice + 1) + relpos) % self.q,
        };

        (l, z)
    }

    pub(crate) fn pass_n(&mut self, pass: u32) {
        if pass == 0 {
            let _h0 = self.h0();

            for lane in 0..self.degree_of_parallelism {
                let index0 = Self::block_index(lane * self.q);
                let index1 = Self::block_index(lane * self.q + 1);
                let mut b_i = [0u8; 72];
                b_i[..64].copy_from_slice(&_h0);
                b_i[68..72].copy_from_slice(&le32(lane));

                b_i[64..68].copy_from_slice(&le32(0u32));
                Self::h_prime(&mut self.blocks[index0], &b_i);

                b_i[64..68].copy_from_slice(&le32(1u32));
                Self::h_prime(&mut self.blocks[index1], &b_i);
            }

            for slice in 0..Self::SL {
                for lane in 0..self.degree_of_parallelism {
                    for sl_block in 0..(self.q / Self::SL) {
                        if slice == 0 && (sl_block == 0 || sl_block == 1) {
                            continue;
                        }
                        let block_in_lane = slice * (self.q / Self::SL) + sl_block;
                        let block = lane * self.q + block_in_lane;
                        let prev_block = self.previous(block);
                        let version = self.version_number;

                        let (l, z) = self.index_l_z(pass, block);
                        let ref_block = l * self.q + z;

                        let (current, previous, reference) =
                            self.get3(block, prev_block, ref_block);

                        match version {
                            Version::V0x10 => Self::g(current, previous, reference),
                            Version::V0x13 => Self::g_xor(current, previous, reference),
                        };
                    }
                }
            }
        } else {
            for slice in 0..Self::SL {
                for lane in 0..self.degree_of_parallelism {
                    for sl_block in 0..(self.q / Self::SL) {
                        let block_in_lane = slice * self.q / Self::SL + sl_block;
                        let block = lane * self.q + block_in_lane;
                        let version = self.version_number;

                        let (l, z) = self.index_l_z(pass, block);

                        let (current, previous, reference) =
                            self.get3(block, self.previous(block), l * self.q + z);

                        match version {
                            Version::V0x10 => Self::g(current, previous, reference),
                            Version::V0x13 => Self::g_xor(current, previous, reference),
                        };
                    }
                }
            }
        }
    }

    pub fn hash(&mut self) -> Vec<u8> {
        for pass in 0..self.number_of_passes {
            self.pass_n(pass);
        }

        let mut c = Vec::new();
        let col = self.q - 1;
        c.extend_from_slice(&self.blocks[Self::block_index(col)]);

        for lane in 1..self.degree_of_parallelism {
            let index = Self::block_index(lane * self.q + col);
            let xor_ = xor(&c[0..Self::BLOCKSIZE as usize], &self.blocks[index]);
            c.splice(0..Self::BLOCKSIZE as usize, xor_);
        }

        let mut output_tag = vec![0; self.tag_length as usize];
        Self::h_prime(&mut output_tag, &c);

        output_tag.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Argon2, Variant, Version};

    const TEST_OUTLEN: u32 = 32;
    const TEST_PWDLEN: usize = 32;
    const TEST_SALTLEN: usize = 16;
    const TEST_SECRETLEN: usize = 8;
    const TEST_ADLEN: usize = 12;

    #[test]
    fn argon2d_rfc_test() {
        let mut argon2 = Argon2::new(
            &[1; TEST_PWDLEN],
            &[2; TEST_SALTLEN],
            4,
            TEST_OUTLEN,
            32,
            3,
            Version::V0x13,
            Some(&[3; TEST_SECRETLEN]),
            Some(&[4; TEST_ADLEN]),
            Variant::Argon2d,
        );

        let hash = argon2.hash();

        /* assert_eq!(&argon2.blocks[..8], {
            let mut a = hex_literal::hex!("db2fea6b2c6f5c8a");
            a.reverse();
            a
        });
        assert_eq!(&argon2.blocks[8..16], {
            let mut a = hex_literal::hex!("719413be00f82634");
            a.reverse();
            a
        });
        assert_eq!(&argon2.blocks[16..24], {
            let mut a = hex_literal::hex!("a1e3f6dd42aa25cc");
            a.reverse();
            a
        });
        assert_eq!(&argon2.blocks[24..32], {
            let mut a = hex_literal::hex!("3ea8efd4d55ac0d1");
            a.reverse();
            a
        });
        assert_eq!(
            &argon2.blocks[31 * Argon2::BLOCKSIZE as usize + 8 * 127
                ..31 * Argon2::BLOCKSIZE as usize + 8 * 128],
            {
                let mut a = hex_literal::hex!("6a6c49d2cb75d5b6");
                a.reverse();
                a
            }
        ); */

        assert_eq!(
            Vec::from(hex_literal::hex!(
                "51 2b 39 1b 6f 11 62 97
     53 71 d3 09 19 73 42 94
     f8 68 e3 be 39 84 f3 c1
     a1 3a 4d b9 fa be 4a cb"
            )),
            hash
        );
    }

    #[test]
    fn g_test() {
        let block_l = [[1u8; 512], [2u8; 512]].concat();
        let block_r = [[3u8; 512], [4u8; 512]].concat();
        let mut block = [0; 1024];
        Argon2::g(&mut block, &block_l, &block_r);

        assert_eq!(
            &block[..64],
            [
                211, 209, 162, 216, 24, 251, 66, 219, 211, 209, 162, 216, 24, 251, 66, 219, 211,
                209, 162, 216, 24, 251, 66, 219, 211, 209, 162, 216, 24, 251, 66, 219, 101, 207,
                31, 252, 145, 181, 138, 61, 101, 207, 31, 252, 145, 181, 138, 61, 101, 207, 31,
                252, 145, 181, 138, 61, 101, 207, 31, 252, 145, 181, 138, 61
            ]
        );
        assert_eq!(
            &block[165..210],
            [
                181, 138, 61, 101, 207, 31, 252, 145, 181, 138, 61, 101, 207, 31, 252, 145, 181,
                138, 61, 101, 207, 31, 252, 145, 181, 138, 61, 38, 115, 43, 119, 34, 195, 54, 91,
                38, 115, 43, 119, 34, 195, 54, 91, 38, 115
            ]
        );
        assert_eq!(
            &block[500..550],
            [
                94, 126, 236, 191, 14, 122, 70, 154, 94, 126, 236, 191, 193, 245, 41, 176, 174, 36,
                209, 230, 193, 245, 41, 176, 174, 36, 209, 230, 193, 245, 41, 176, 174, 36, 209,
                230, 193, 245, 41, 176, 174, 36, 209, 230, 115, 100, 14, 169, 242, 250
            ]
        );
        assert_eq!(
            &block[960..1024],
            [
                90, 107, 183, 128, 101, 176, 78, 167, 90, 107, 183, 128, 101, 176, 78, 167, 90,
                107, 183, 128, 101, 176, 78, 167, 90, 107, 183, 128, 101, 176, 78, 167, 46, 145,
                29, 147, 149, 19, 222, 76, 46, 145, 29, 147, 149, 19, 222, 76, 46, 145, 29, 147,
                149, 19, 222, 76, 46, 145, 29, 147, 149, 19, 222, 76
            ]
        );
    }

    #[test]
    fn p_test() {
        let mut row = [
            66, 255, 212, 161, 8, 171, 78, 110, 75, 86, 181, 135, 167, 234, 13, 72, 45, 223, 197,
            187, 49, 168, 13, 188, 61, 245, 106, 226, 93, 243, 1, 255, 237, 245, 168, 57, 94, 191,
            149, 148, 10, 230, 130, 73, 122, 204, 228, 164, 241, 5, 252, 19, 102, 160, 174, 157,
            217, 241, 78, 140, 75, 182, 40, 211, 157, 4, 66, 250, 45, 81, 90, 73, 247, 35, 144, 93,
            204, 96, 88, 34, 36, 149, 228, 27, 134, 173, 75, 52, 90, 94, 217, 185, 101, 191, 46,
            33, 19, 148, 217, 81, 229, 176, 71, 82, 242, 140, 128, 32, 10, 56, 171, 242, 87, 94,
            213, 122, 49, 37, 77, 215, 171, 226, 98, 95, 39, 210, 190, 108,
        ];
        Argon2::p(&mut row);

        assert_eq!(
            row,
            [
                54, 227, 42, 202, 146, 116, 88, 136, 74, 130, 230, 219, 16, 144, 210, 147, 163,
                142, 132, 246, 56, 219, 231, 74, 14, 50, 49, 173, 190, 14, 69, 51, 95, 208, 53,
                152, 36, 57, 85, 176, 55, 220, 20, 186, 210, 144, 226, 218, 200, 116, 224, 132,
                183, 211, 60, 167, 130, 23, 155, 185, 226, 211, 84, 87, 128, 40, 151, 113, 3, 135,
                50, 27, 240, 91, 97, 212, 127, 101, 185, 216, 6, 190, 87, 89, 35, 14, 187, 22, 206,
                58, 13, 13, 218, 11, 71, 71, 22, 78, 154, 131, 226, 122, 188, 30, 234, 189, 38,
                249, 23, 14, 213, 197, 94, 125, 210, 149, 209, 34, 57, 247, 69, 228, 36, 85, 119,
                223, 134, 141
            ]
        );
    }

    #[test]
    fn p_row_test() {
        let mut block = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].repeat(8),
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7].repeat(8),
            [0, 1, 2, 3, 4, 5, 6, 7, 3, 2, 2, 1, 1, 1, 1, 1].repeat(8),
            [1, 2, 3, 1, 2, 3, 1, 2, 8, 9, 10, 18, 12, 13, 14, 15].repeat(8),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].repeat(8),
            [0, 1, 2, 3, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10, 9, 8].repeat(8),
            [7, 6, 5, 4, 3, 2, 1, 0, 8, 9, 10, 11, 12, 13, 14, 15].repeat(8),
            [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0].repeat(8),
        ]
        .concat();

        for row in 0..8 {
            Argon2::p(&mut block[128 * row..128 * (row + 1)]);
        }

        assert_eq!(
            &block[..],
            [
                71, 142, 86, 16, 70, 165, 123, 1, 141, 92, 101, 0, 213, 100, 219, 119, 71, 142, 86,
                16, 70, 165, 123, 1, 141, 92, 101, 0, 213, 100, 219, 119, 58, 153, 56, 157, 214,
                183, 0, 165, 174, 62, 248, 44, 73, 206, 202, 145, 58, 153, 56, 157, 214, 183, 0,
                165, 174, 62, 248, 44, 73, 206, 202, 145, 30, 235, 173, 170, 227, 6, 225, 76, 193,
                28, 35, 221, 148, 243, 53, 226, 30, 235, 173, 170, 227, 6, 225, 76, 193, 28, 35,
                221, 148, 243, 53, 226, 207, 213, 172, 29, 123, 5, 96, 131, 38, 28, 137, 27, 103,
                108, 199, 198, 207, 213, 172, 29, 123, 5, 96, 131, 38, 28, 137, 27, 103, 108, 199,
                198, 225, 158, 60, 251, 241, 219, 202, 100, 225, 158, 60, 251, 241, 219, 202, 100,
                225, 158, 60, 251, 241, 219, 202, 100, 225, 158, 60, 251, 241, 219, 202, 100, 206,
                237, 106, 218, 243, 160, 108, 164, 206, 237, 106, 218, 243, 160, 108, 164, 206,
                237, 106, 218, 243, 160, 108, 164, 206, 237, 106, 218, 243, 160, 108, 164, 131, 11,
                114, 9, 86, 94, 111, 39, 131, 11, 114, 9, 86, 94, 111, 39, 131, 11, 114, 9, 86, 94,
                111, 39, 131, 11, 114, 9, 86, 94, 111, 39, 43, 111, 164, 238, 18, 107, 241, 16, 43,
                111, 164, 238, 18, 107, 241, 16, 43, 111, 164, 238, 18, 107, 241, 16, 43, 111, 164,
                238, 18, 107, 241, 16, 41, 113, 51, 13, 134, 234, 205, 96, 158, 17, 62, 218, 102,
                12, 247, 149, 41, 113, 51, 13, 134, 234, 205, 96, 158, 17, 62, 218, 102, 12, 247,
                149, 18, 117, 112, 112, 55, 60, 203, 97, 111, 126, 158, 164, 163, 92, 195, 173, 18,
                117, 112, 112, 55, 60, 203, 97, 111, 126, 158, 164, 163, 92, 195, 173, 43, 154,
                110, 238, 249, 131, 173, 33, 144, 180, 175, 196, 221, 177, 121, 190, 43, 154, 110,
                238, 249, 131, 173, 33, 144, 180, 175, 196, 221, 177, 121, 190, 253, 103, 65, 135,
                235, 160, 249, 84, 0, 102, 101, 196, 174, 239, 234, 62, 253, 103, 65, 135, 235,
                160, 249, 84, 0, 102, 101, 196, 174, 239, 234, 62, 217, 109, 227, 171, 84, 62, 95,
                197, 209, 44, 13, 182, 249, 117, 171, 109, 217, 109, 227, 171, 84, 62, 95, 197,
                209, 44, 13, 182, 249, 117, 171, 109, 6, 16, 208, 19, 249, 41, 203, 156, 34, 113,
                79, 147, 251, 181, 235, 28, 6, 16, 208, 19, 249, 41, 203, 156, 34, 113, 79, 147,
                251, 181, 235, 28, 29, 227, 201, 142, 209, 250, 1, 89, 114, 61, 38, 149, 5, 135,
                192, 99, 29, 227, 201, 142, 209, 250, 1, 89, 114, 61, 38, 149, 5, 135, 192, 99,
                151, 28, 15, 185, 192, 14, 208, 20, 96, 112, 194, 146, 218, 168, 51, 60, 151, 28,
                15, 185, 192, 14, 208, 20, 96, 112, 194, 146, 218, 168, 51, 60, 71, 142, 86, 16,
                70, 165, 123, 1, 141, 92, 101, 0, 213, 100, 219, 119, 71, 142, 86, 16, 70, 165,
                123, 1, 141, 92, 101, 0, 213, 100, 219, 119, 58, 153, 56, 157, 214, 183, 0, 165,
                174, 62, 248, 44, 73, 206, 202, 145, 58, 153, 56, 157, 214, 183, 0, 165, 174, 62,
                248, 44, 73, 206, 202, 145, 30, 235, 173, 170, 227, 6, 225, 76, 193, 28, 35, 221,
                148, 243, 53, 226, 30, 235, 173, 170, 227, 6, 225, 76, 193, 28, 35, 221, 148, 243,
                53, 226, 207, 213, 172, 29, 123, 5, 96, 131, 38, 28, 137, 27, 103, 108, 199, 198,
                207, 213, 172, 29, 123, 5, 96, 131, 38, 28, 137, 27, 103, 108, 199, 198, 77, 211,
                81, 6, 141, 202, 155, 27, 215, 81, 73, 88, 17, 9, 20, 229, 77, 211, 81, 6, 141,
                202, 155, 27, 215, 81, 73, 88, 17, 9, 20, 229, 19, 144, 206, 226, 246, 228, 132,
                195, 75, 26, 140, 72, 115, 75, 78, 157, 19, 144, 206, 226, 246, 228, 132, 195, 75,
                26, 140, 72, 115, 75, 78, 157, 240, 98, 96, 92, 69, 79, 91, 47, 9, 0, 72, 57, 213,
                35, 58, 42, 240, 98, 96, 92, 69, 79, 91, 47, 9, 0, 72, 57, 213, 35, 58, 42, 78,
                104, 134, 178, 141, 117, 48, 13, 133, 130, 56, 111, 166, 52, 212, 1, 78, 104, 134,
                178, 141, 117, 48, 13, 133, 130, 56, 111, 166, 52, 212, 1, 70, 127, 105, 245, 235,
                154, 230, 194, 62, 42, 82, 163, 114, 164, 119, 20, 70, 127, 105, 245, 235, 154,
                230, 194, 62, 42, 82, 163, 114, 164, 119, 20, 69, 157, 89, 186, 106, 169, 93, 201,
                235, 87, 242, 28, 52, 184, 13, 224, 69, 157, 89, 186, 106, 169, 93, 201, 235, 87,
                242, 28, 52, 184, 13, 224, 78, 187, 198, 212, 253, 246, 61, 154, 127, 253, 31, 162,
                106, 184, 72, 48, 78, 187, 198, 212, 253, 246, 61, 154, 127, 253, 31, 162, 106,
                184, 72, 48, 95, 116, 31, 3, 134, 88, 53, 0, 77, 9, 99, 246, 245, 46, 3, 168, 95,
                116, 31, 3, 134, 88, 53, 0, 77, 9, 99, 246, 245, 46, 3, 168, 75, 220, 31, 63, 47,
                57, 46, 110, 45, 7, 64, 59, 58, 33, 116, 221, 75, 220, 31, 63, 47, 57, 46, 110, 45,
                7, 64, 59, 58, 33, 116, 221, 144, 206, 245, 40, 187, 115, 178, 171, 35, 115, 68,
                201, 200, 206, 11, 237, 144, 206, 245, 40, 187, 115, 178, 171, 35, 115, 68, 201,
                200, 206, 11, 237, 55, 189, 5, 177, 229, 16, 255, 140, 106, 199, 161, 133, 14, 181,
                56, 69, 55, 189, 5, 177, 229, 16, 255, 140, 106, 199, 161, 133, 14, 181, 56, 69,
                173, 40, 232, 81, 254, 61, 132, 143, 36, 56, 104, 215, 204, 173, 224, 247, 173, 40,
                232, 81, 254, 61, 132, 143, 36, 56, 104, 215, 204, 173, 224, 247
            ]
        );
    }

    #[test]
    fn p_col_test() {
        const COL: usize = 7;
        let mut block = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].repeat(16),
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7].repeat(16),
            [0, 1, 2, 3, 4, 5, 6, 7, 3, 2, 2, 1, 1, 1, 1, 1].repeat(16),
            [1, 2, 3, 1, 2, 3, 1, 2, 8, 9, 10, 18, 12, 13, 14, 15].repeat(16),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].repeat(16),
            [0, 1, 2, 3, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10, 9, 8].repeat(16),
            [7, 6, 5, 4, 3, 2, 1, 0, 8, 9, 10, 11, 12, 13, 14, 15].repeat(16),
            [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0].repeat(16),
        ]
        .concat();

        Argon2::transpose(&mut block, 8);

        Argon2::p(&mut block[128 * COL..128 * (COL + 1)]);

        Argon2::transpose(&mut block, 8);

        assert_eq!(
            &block[COL * 16..(COL + 1) * 16],
            [38, 164, 141, 30, 21, 16, 24, 131, 176, 183, 169, 68, 53, 100, 79, 96]
        );
        assert_eq!(
            &block[128 + COL * 16..128 + (COL + 1) * 16],
            [38, 164, 141, 30, 21, 16, 24, 131, 176, 183, 169, 68, 53, 100, 79, 96]
        );
        assert_eq!(
            &block[128 * 2 + COL * 16..128 * 2 + (COL + 1) * 16],
            [49, 181, 175, 146, 188, 135, 20, 128, 96, 196, 131, 182, 143, 10, 105, 239]
        );
        assert_eq!(
            &block[128 * 3 + COL * 16..128 * 3 + (COL + 1) * 16],
            [49, 181, 175, 146, 188, 135, 20, 128, 96, 196, 131, 182, 143, 10, 105, 239]
        );
        assert_eq!(
            &block[128 * 4 + COL * 16..128 * 4 + (COL + 1) * 16],
            [222, 56, 125, 108, 220, 83, 39, 134, 13, 205, 130, 155, 126, 89, 194, 228]
        );
        assert_eq!(
            &block[128 * 5 + COL * 16..128 * 5 + (COL + 1) * 16],
            [222, 56, 125, 108, 220, 83, 39, 134, 13, 205, 130, 155, 126, 89, 194, 228]
        );
        assert_eq!(
            &block[128 * 6 + COL * 16..128 * 6 + (COL + 1) * 16],
            [61, 188, 17, 208, 163, 24, 43, 150, 120, 117, 72, 51, 199, 111, 237, 43]
        );
        assert_eq!(
            &block[128 * 7 + COL * 16..128 * 7 + (COL + 1) * 16],
            [61, 188, 17, 208, 163, 24, 43, 150, 120, 117, 72, 51, 199, 111, 237, 43]
        );
    }

    #[test]
    fn gb_test() {
        let mut a = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut b = [8, 9, 10, 11, 12, 13, 14, 15];
        let mut c = [3u8; 8];
        let mut d = [4u8; 8];

        unsafe {
            Argon2::gb(
                a.as_mut_ptr(),
                b.as_mut_ptr(),
                c.as_mut_ptr(),
                d.as_mut_ptr(),
            )
        }

        assert_eq!(a, [138, 103, 0, 49, 61, 182, 158, 224]);
        assert_eq!(b, [70, 157, 217, 235, 246, 28, 26, 83]);
        assert_eq!(c, [193, 161, 159, 208, 1, 133, 252, 24]);
        assert_eq!(d, [82, 35, 49, 168, 164, 146, 10, 25]);
    }

    #[test]
    fn h_prime_test() {
        let mut out = [0u8; 1024];
        Argon2::h_prime(&mut out, &[2; 32]);
        assert_eq!(
            &out[0..64],
            [
                144, 22, 171, 122, 254, 43, 27, 121, 35, 151, 157, 214, 91, 253, 233, 241, 65, 100,
                71, 250, 138, 217, 217, 33, 107, 15, 138, 39, 248, 201, 1, 77, 182, 211, 240, 195,
                84, 242, 192, 120, 49, 34, 241, 76, 2, 128, 210, 241, 224, 180, 178, 75, 29, 52,
                140, 141, 9, 166, 46, 113, 209, 183, 240, 164
            ]
        );
    }

    #[test]
    fn h0_argon2id_rfc_test() {
        let argon2 = Argon2::new(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            Version::V0x13,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Variant::Argon2id,
        );
        assert_eq!(
            argon2.h0(),
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
        let argon2 = Argon2::new(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            Version::V0x13,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Variant::Argon2d,
        );

        assert_eq!(
            argon2.h0(),
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
        let argon2 = Argon2::new(
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            4,
            32,
            32,
            3,
            Version::V0x13,
            Some(&[3, 3, 3, 3, 3, 3, 3, 3]),
            Some(&[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
            Variant::Argon2i,
        );
        assert_eq!(
            argon2.h0(),
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
