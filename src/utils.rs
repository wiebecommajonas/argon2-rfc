#[macro_export]
macro_rules! vec_from_slices {
    ( $($s:expr),+) => {
        {
            let mut vec = Vec::new();
            $(
                vec.extend_from_slice($s);
            )+
            vec
        }
    };
}

pub(crate) fn le32<U>(input: U) -> [u8; 4]
where
    U: Into<u32>,
{
    Into::<u32>::into(input).to_le_bytes()
}

pub(crate) fn le64<U>(input: U) -> [u8; 8]
where
    U: Into<u64>,
{
    Into::<u64>::into(input).to_le_bytes()
}

pub(crate) fn lo(x: u64) -> u64 {
    x & 0xffffffff
}

pub(crate) fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .map(|(a_, b_)| a_ ^ b_)
        .collect::<Vec<u8>>()
}

#[macro_export]
macro_rules! b2hash {
    ($($bytes: expr),*) => {
        {
            let mut out = [0u8; 64];
            b2hash!(&mut out; $($bytes),*);
            out
        }
    };
    ($out: expr; $($bytes: expr),*) => {
        {
            use blake2_rfc::blake2b::Blake2b;
            let mut b = Blake2b::new($out.len());
            $(b.update($bytes));*;
            $out.clone_from_slice(b.finalize().as_bytes());
        }
    };
}
