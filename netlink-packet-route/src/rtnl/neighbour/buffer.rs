use crate::{
    rtnl::nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const HEADER_LEN: usize = 12;
buffer!(MessageBuffer(HEADER_LEN) {
    family: (u8, 0),
    ifindex: (u32, 4..8),
    state: (u16, 8..10),
    flags: (u8, 10),
    ntype: (u8, 11),
    payload:(slice, HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> MessageBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}
