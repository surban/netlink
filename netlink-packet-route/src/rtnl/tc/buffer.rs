use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const HEADER_LEN: usize = 20;

buffer!(MessageBuffer(HEADER_LEN) {
    family: (u8, 0),
    pad1: (u8, 1),
    pad2: (u16, 2..4),
    index: (i32, 4..8),
    handle: (u32, 8..12),
    parent: (u32, 12..16),
    info: (u32, 16..HEADER_LEN),
    payload: (slice, HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> MessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}
