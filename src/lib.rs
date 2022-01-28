#![allow(clippy::many_single_char_names)]
mod utils;

use std::{
    convert::TryInto,
    fmt::Display,
    num::Wrapping,
    ops::Range,
    slice::{from_raw_parts, from_raw_parts_mut},
};
use utils::{le32, le64};

#[derive(Copy, Clone, PartialEq)]
pub enum Variant {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

impl Display for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Argon2d => write!(f, "argon2d")?,
            Self::Argon2i => write!(f, "argon2i")?,
            Self::Argon2id => write!(f, "argon2id")?,
        }
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum Version {
    V0x10 = 0x10,
    V0x13 = 0x13,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u32)?;
        Ok(())
    }
}

pub struct Argon2 {
    degree_of_parallelism: u32,
    memory_size: u32,
    number_of_passes: u32,
    version: Version,
    argon2_type: Variant,
    m_prime: u32,
    lanelen: u32,
    slicelen: u32,
}

type BlockIndex = Range<usize>;

impl Argon2 {
    pub const SL: u32 = 4;
    pub const BLOCKSIZE: u32 = 1024;
    pub const INDEX_BITSHIFT: u32 = 10;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        degree_of_parallelism: u32,
        number_of_passes: u32,
        memory_size: u32,
        version: Version,
        argon2_type: Variant,
    ) -> Self {
        assert!(
            (1..=16777215).contains(&degree_of_parallelism),
            "Degree of parralellism invalid"
        );
        assert!(
            memory_size >= 8 * degree_of_parallelism,
            "Memory size invalid"
        );
        assert!(number_of_passes >= 1, "Number of passes invalid");

        let m_prime = 4 * degree_of_parallelism * (memory_size / (4 * degree_of_parallelism));
        let q = m_prime / degree_of_parallelism;

        Self {
            degree_of_parallelism,
            memory_size,
            number_of_passes,
            version,
            argon2_type,
            m_prime,
            lanelen: q,
            slicelen: q / Self::SL,
        }
    }

    #[inline(always)]
    fn block_index(block: u32) -> BlockIndex {
        let index = (block << Self::INDEX_BITSHIFT) as usize;
        index..index + Self::BLOCKSIZE as usize
    }

    #[inline(always)]
    fn partial_block_index(block: u32, from: usize, to: usize) -> BlockIndex {
        let index = (block << Self::INDEX_BITSHIFT) as usize;
        index + from..index + to
    }

    fn previous(&self, block: u32) -> u32 {
        let lane = block / self.lanelen;
        let mut block_in_lane = block % self.lanelen;
        if block_in_lane > 0 {
            block_in_lane -= 1;
        } else {
            block_in_lane = self.lanelen - 1
        }

        lane * self.lanelen + block_in_lane
    }

    fn blocks(blocks: &mut [u8], a: u32, b: u32, c: u32) -> (&mut [u8], &[u8], &[u8]) {
        let mptr = blocks.as_mut_ptr();
        let ptr = blocks.as_ptr();
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

    fn h_prime(dest: &mut [u8], input: &[u8]) {
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

    fn h0(
        &self,
        taglen: u32,
        password: &[u8],
        salt: &[u8],
        secret: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> [u8; 64] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&le32(self.degree_of_parallelism));
        bytes.extend_from_slice(&le32(taglen));
        bytes.extend_from_slice(&le32(self.memory_size));
        bytes.extend_from_slice(&le32(self.number_of_passes));
        bytes.extend_from_slice(&le32(self.version as u32));
        bytes.extend_from_slice(&le32(self.argon2_type as u32));
        bytes.extend_from_slice(&le32(password.len() as u32));
        bytes.extend_from_slice(password);
        if salt.is_empty() {
            bytes.extend_from_slice(&le32(0_u32));
        } else {
            bytes.extend_from_slice(&le32(salt.len() as u32));
            bytes.extend_from_slice(salt);
        }
        if let Some(secret) = secret {
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

        b2hash!(&bytes)
    }

    fn transpose(block: &mut [u8], dims: usize) {
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

    fn g(dest: &mut [u8], x: &[u8], y: &[u8]) {
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

    fn g_xor(dest: &mut [u8], x: &[u8], y: &[u8]) {
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

    fn p(input: &mut [u8]) {
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

    unsafe fn gb(a_: *mut u8, b_: *mut u8, c_: *mut u8, d_: *mut u8) {
        let mut a = u64::from_le_bytes(from_raw_parts_mut(a_, 8).as_ref().try_into().unwrap());
        let mut b = u64::from_le_bytes(from_raw_parts_mut(b_, 8).as_ref().try_into().unwrap());
        let mut c = u64::from_le_bytes(from_raw_parts_mut(c_, 8).as_ref().try_into().unwrap());
        let mut d = u64::from_le_bytes(from_raw_parts_mut(d_, 8).as_ref().try_into().unwrap());

        a = (Wrapping(a) + Wrapping(b) + Wrapping(2) * Wrapping(lo!(a)) * Wrapping(lo!(b))).0;
        d = (d ^ a).rotate_right(32);
        c = (Wrapping(c) + Wrapping(d) + Wrapping(2) * Wrapping(lo!(c)) * Wrapping(lo!(d))).0;
        b = (b ^ c).rotate_right(24);

        a = (Wrapping(a) + Wrapping(b) + Wrapping(2) * Wrapping(lo!(a)) * Wrapping(lo!(b))).0;
        d = (d ^ a).rotate_right(16);
        c = (Wrapping(c) + Wrapping(d) + Wrapping(2) * Wrapping(lo!(c)) * Wrapping(lo!(d))).0;
        b = (b ^ c).rotate_right(63);

        a_.copy_from_nonoverlapping(a.to_le_bytes().as_ptr(), 8);
        b_.copy_from_nonoverlapping(b.to_le_bytes().as_ptr(), 8);
        c_.copy_from_nonoverlapping(c.to_le_bytes().as_ptr(), 8);
        d_.copy_from_nonoverlapping(d.to_le_bytes().as_ptr(), 8);
    }

    fn index_j_d(&self, blocks: &mut [u8], block: u32) -> (u32, u32) {
        let prev_block = self.previous(block);
        let prev_block_index_one = Self::partial_block_index(prev_block, 0, 4);
        let prev_block_index_two = Self::partial_block_index(prev_block, 4, 8);

        let j_1 = u32::from_le_bytes(blocks[prev_block_index_one].as_ref().try_into().unwrap());
        let j_2 = u32::from_le_bytes(blocks[prev_block_index_two].as_ref().try_into().unwrap());

        (j_1, j_2)
    }

    fn index_l_z(&self, pass: u32, block: u32, j_1: u32, j_2: u32) -> (u32, u32) {
        let lane = block / self.lanelen;
        let block_in_lane = block % self.lanelen;
        let slice = block_in_lane / self.slicelen;
        let sliceidx = block_in_lane % self.slicelen;

        let l = match (slice, pass) {
            (0, 0) => lane,
            _ => j_2 % self.degree_of_parallelism,
        };

        let w = match (pass, slice, j_2 % self.degree_of_parallelism == lane) {
            (0, 0, _) => sliceidx - 1,
            (0, _, false) => slice * self.slicelen - if sliceidx == 0 { 1 } else { 0 },
            (0, _, true) => slice * self.slicelen + sliceidx - 1,
            (_, _, false) => self.lanelen - self.slicelen - if sliceidx == 0 { 1 } else { 0 },
            (_, _, true) => self.lanelen - self.slicelen + sliceidx - 1,
        };

        let (w_, j1_) = (w as u64, j_1 as u64);
        let relpos = (w_ - 1 - (w_ * (j1_ * j1_ >> 32) >> 32)) as u32;

        let z = match (pass, slice) {
            (0, _) | (_, 3) => relpos % self.lanelen,
            _ => (self.slicelen * (slice + 1) + relpos) % self.lanelen,
        };

        (l, z)
    }

    fn compute_first_slice(&self, blocks: &mut [u8], h0: &[u8; 64], lane: u32) {
        let index0 = Self::block_index(lane * self.lanelen);
        let index1 = Self::block_index(lane * self.lanelen + 1);
        let mut b_i = [0u8; 72];
        b_i[..64].copy_from_slice(h0);
        b_i[68..72].copy_from_slice(&le32(lane));

        b_i[64..68].copy_from_slice(&le32(0u32));
        Self::h_prime(&mut blocks[index0], &b_i);

        b_i[64..68].copy_from_slice(&le32(1u32));
        Self::h_prime(&mut blocks[index1], &b_i);

        self.compute_slice(blocks, 0, lane, 0, 2);
    }

    fn compute_slice(&self, blocks: &mut [u8], pass: u32, lane: u32, slice: u32, offset: u32) {
        let mut index_generator = IndexGenerator::new(
            offset as usize,
            pass,
            lane,
            slice,
            self.m_prime,
            self.number_of_passes,
            self.argon2_type,
        );
        for sliceidx in offset..self.slicelen {
            let block_in_lane = slice * self.slicelen + sliceidx;
            let block = lane * self.lanelen + block_in_lane;

            let (j_1, j_2) = match (self.argon2_type, pass, slice) {
                (Variant::Argon2id, 0, 0) | (Variant::Argon2id, 0, 1) => {
                    index_generator.next().unwrap()
                }
                (Variant::Argon2d, _, _) | (Variant::Argon2id, _, _) => {
                    self.index_j_d(blocks, block)
                }
                _ => index_generator.next().unwrap(),
            };
            let (l, z) = self.index_l_z(pass, block, j_1, j_2);

            let (current, previous, reference) =
                Self::blocks(blocks, block, self.previous(block), l * self.lanelen + z);

            match self.version {
                Version::V0x10 => Self::g(current, previous, reference),
                Version::V0x13 => Self::g_xor(current, previous, reference),
            };
        }
    }

    pub fn hash<const TAGLEN: usize>(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> [u8; TAGLEN] {
        assert!(password.len() < u32::MAX as usize, "Password is too long");
        assert!(salt.len() < u32::MAX as usize, "Salt is too long");
        if let Some(secret) = secret {
            assert!(secret.len() <= u32::MAX as usize, "Secret is too long");
        }
        if let Some(associated) = associated_data {
            assert!(
                associated.len() <= u32::MAX as usize,
                "Associated data is too long"
            );
        }

        let mut blocks = vec![0u8; self.m_prime as usize * 1024];

        let h0_ = self.h0(TAGLEN as u32, password, salt, secret, associated_data);

        for lane in 0..self.degree_of_parallelism {
            self.compute_first_slice(&mut blocks, &h0_, lane);
        }

        for slice in 1..Self::SL {
            for lane in 0..self.degree_of_parallelism {
                self.compute_slice(&mut blocks, 0, lane, slice, 0);
            }
        }

        for pass in 1..self.number_of_passes {
            for slice in 0..Self::SL {
                for lane in 0..self.degree_of_parallelism {
                    self.compute_slice(&mut blocks, pass, lane, slice, 0);
                }
            }
        }

        let mut c = [0; 1024];
        let col = self.lanelen - 1;
        c[..].copy_from_slice(&blocks[Self::block_index(col)]);

        for lane in 1..self.degree_of_parallelism {
            let index = Self::block_index(lane * self.lanelen + col);
            for (c_, b_) in c.iter_mut().zip(blocks[index].iter()) {
                *c_ ^= b_;
            }
        }

        let mut output_tag = [0; TAGLEN];
        Self::h_prime(&mut output_tag, &c);

        output_tag
    }

    pub fn hash_as_encoded_string<const TAGLEN: usize>(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> String {
        let hash = self.hash::<TAGLEN>(password, salt, secret, associated_data);
        format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.argon2_type,
            self.version,
            self.memory_size,
            self.number_of_passes,
            self.degree_of_parallelism,
            base64::encode_config(&salt, base64::STANDARD_NO_PAD),
            base64::encode_config(&hash, base64::STANDARD_NO_PAD)
        )
    }

    pub fn variable_hash(
        &self,
        taglen: u32,
        password: &[u8],
        salt: &[u8],
        secret: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> Vec<u8> {
        assert!(password.len() < u32::MAX as usize, "Password is too long");
        assert!(salt.len() < u32::MAX as usize, "Salt is too long");
        if let Some(secret) = secret {
            assert!(secret.len() <= u32::MAX as usize, "Secret is too long");
        }
        if let Some(associated) = associated_data {
            assert!(
                associated.len() <= u32::MAX as usize,
                "Associated data is too long"
            );
        }

        let mut blocks = vec![0u8; self.m_prime as usize * 1024];

        let h0_ = self.h0(taglen, password, salt, secret, associated_data);

        for lane in 0..self.degree_of_parallelism {
            self.compute_first_slice(&mut blocks, &h0_, lane);
        }

        for slice in 1..Self::SL {
            for lane in 0..self.degree_of_parallelism {
                self.compute_slice(&mut blocks, 0, lane, slice, 0);
            }
        }

        for pass in 1..self.number_of_passes {
            for slice in 0..Self::SL {
                for lane in 0..self.degree_of_parallelism {
                    self.compute_slice(&mut blocks, pass, lane, slice, 0);
                }
            }
        }

        let mut c = [0; 1024];
        let col = self.lanelen - 1;
        c[..].copy_from_slice(&blocks[Self::block_index(col)]);

        for lane in 1..self.degree_of_parallelism {
            let index = Self::block_index(lane * self.lanelen + col);
            for (c_, b_) in c.iter_mut().zip(blocks[index].iter()) {
                *c_ ^= b_;
            }
        }

        let mut output_tag = vec![0; taglen as usize];
        Self::h_prime(&mut output_tag, &c);

        output_tag
    }

    pub fn variable_hash_as_encoded_string(
        &self,
        taglen: u32,
        password: &[u8],
        salt: &[u8],
        secret: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> String {
        let hash = self.variable_hash(taglen, password, salt, secret, associated_data);
        format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.argon2_type,
            self.version,
            self.memory_size,
            self.number_of_passes,
            self.degree_of_parallelism,
            base64::encode_config(&salt, base64::STANDARD_NO_PAD),
            base64::encode_config(&hash, base64::STANDARD_NO_PAD)
        )
    }
}

struct IndexGenerator {
    z_block: [u8; 1024],
    reference: [u8; 1024],
    index: usize,
}

impl Iterator for IndexGenerator {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        let a = u64::from_le_bytes(
            self.reference[8 * self.index..8 * (self.index + 1)]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        let js = (lo!(a) as u32, hi!(a) as u32);
        self.index = (self.index + 1) % 128;
        if self.index == 0 {
            let mut i = u64::from_le_bytes(self.z_block[48..56].as_ref().try_into().unwrap());
            i += 1;
            self.z_block[48..56].copy_from_slice(&i.to_le_bytes());

            let mut reference = [0; 1024];
            let mut tmp = [0; 1024];

            Argon2::g(&mut tmp, &[0; 1024], &self.z_block);
            Argon2::g(&mut reference, &[0; 1024], &tmp);
            self.reference = reference;
        }

        Some(js)
    }
}

impl IndexGenerator {
    fn new(
        index: usize,
        pass: u32,
        lane: u32,
        slice: u32,
        total_blocks: u32,
        total_passes: u32,
        argon2_type: Variant,
    ) -> Self {
        let mut z = [0; 1024];
        z[..56].copy_from_slice(
            &[
                le64(pass),
                le64(lane),
                le64(slice),
                le64(total_blocks),
                le64(total_passes),
                le64(argon2_type as u64),
                le64(1u64),
            ]
            .concat(),
        );
        let mut reference = [0; 1024];
        let mut tmp = [0; 1024];

        Argon2::g(&mut tmp, &[0; 1024], &z);
        Argon2::g(&mut reference, &[0; 1024], &tmp);

        Self {
            z_block: z,
            reference,
            index,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Argon2, Variant, Version};

    const OUTLEN: usize = 32;
    const PASSWORDLEN: usize = 32;
    const SALTLEN: usize = 16;
    const SECRETLEN: usize = 8;
    const ASSOCIATEDLEN: usize = 12;

    #[test]
    fn argon2d_rfc_test() {
        let mut argon2 = Argon2::new(4, 3, 32, Version::V0x13, Variant::Argon2d);

        let hash = argon2.hash::<OUTLEN>(
            &[1; PASSWORDLEN],
            &[2; SALTLEN],
            Some(&[3; SECRETLEN]),
            Some(&[4; ASSOCIATEDLEN]),
        );

        assert_eq!(
            hex_literal::hex!(
                "51 2b 39 1b 6f 11 62 97
     53 71 d3 09 19 73 42 94
     f8 68 e3 be 39 84 f3 c1
     a1 3a 4d b9 fa be 4a cb"
            ),
            hash
        );
    }

    #[test]
    fn argon2i_rfc_test() {
        let mut argon2 = Argon2::new(4, 3, 32, Version::V0x13, Variant::Argon2i);

        let hash = argon2.hash::<OUTLEN>(
            &[1; PASSWORDLEN],
            &[2; SALTLEN],
            Some(&[3; SECRETLEN]),
            Some(&[4; ASSOCIATEDLEN]),
        );

        assert_eq!(
            hex_literal::hex!(
                "c8 14 d9 d1 dc 7f 37 aa
     13 f0 d7 7f 24 94 bd a1
     c8 de 6b 01 6d d3 88 d2
     99 52 a4 c4 67 2b 6c e8"
            ),
            hash
        );
    }

    #[test]
    fn argon2id_rfc_test() {
        let mut argon2 = Argon2::new(4, 3, 32, Version::V0x13, Variant::Argon2id);

        let hash = argon2.hash::<OUTLEN>(
            &[1; PASSWORDLEN],
            &[2; SALTLEN],
            Some(&[3; SECRETLEN]),
            Some(&[4; ASSOCIATEDLEN]),
        );

        assert_eq!(
            hex_literal::hex!(
                "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0
 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59"
            ),
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
}
