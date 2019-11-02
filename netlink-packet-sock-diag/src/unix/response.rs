use failure::ResultExt;
use smallvec::SmallVec;
use std::{convert::TryFrom, time::Duration};

use crate::{
    constants::*,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

pub const UNIX_RESPONSE_HEADER_LEN: usize = 16;

buffer!(UnixResponseBuffer(UNIX_RESPONSE_HEADER_LEN) {
    family: (u8, 0),
    kind: (u8, 1),
    state: (u8, 2),
    pad: (u8, 3),
    inode: (u32, 4..8),
    cookie: (slice, 8..UNIX_RESPONSE_HEADER_LEN),
    payload: (slice, UNIX_RESPONSE_HEADER_LEN..),
});

/// The response to a query for IPv4 or IPv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnixResponseHeader {
    /// One of `SOCK_PACKET`, `SOCK_STREAM`, or `SOCK_SEQPACKET`
    pub kind: u8,
    /// One of `TCP_LISTEN` or `TCP_ESTABLISHED`
    pub state: u8,
    /// Socket inode number.
    pub inode: u32,
    pub cookie: [u8; 8],
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<UnixResponseBuffer<&'a T>> for UnixResponseHeader {
    fn parse(buf: &UnixResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: buf.kind(),
            state: buf.state(),
            inode: buf.inode(),
            // Unwrapping is safe because UnixResponseBuffer::cookie()
            // returns a slice of exactly 8 bytes.
            cookie: TryFrom::try_from(buf.cookie()).unwrap(),
        })
    }
}

impl Emitable for UnixResponseHeader {
    fn buffer_len(&self) -> usize {
        UNIX_RESPONSE_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = UnixResponseBuffer::new(buf);
        buf.set_family(AF_UNIX as u8);
        buf.set_kind(self.kind);
        buf.set_state(self.state);
        buf.set_pad(0);
        buf.set_inode(self.inode);
        buf.cookie_mut().copy_from_slice(&self.cookie[..]);
    }
}
//
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct UnixResponse {
//     pub header: UnixResponseHeader,
//     pub nlas: SmallVec<[Nla; 8]>,
// }
//
// impl<'a, T: AsRef<[u8]> + ?Sized> UnixResponseBuffer<&'a T> {
//     pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
//         NlasIterator::new(self.payload())
//     }
// }
//
// impl<'a, T: AsRef<[u8]> + 'a> Parseable<UnixResponseBuffer<&'a T>> for SmallVec<[Nla; 8]> {
//     fn parse(buf: &UnixResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
//         let mut nlas = smallvec![];
//         for nla_buf in buf.nlas() {
//             nlas.push(Nla::parse(&nla_buf?)?);
//         }
//         Ok(nlas)
//     }
// }
//
// impl<'a, T: AsRef<[u8]> + 'a> Parseable<UnixResponseBuffer<&'a T>> for UnixResponse {
//     fn parse(buf: &UnixResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
//         let header =
//             UnixResponseHeader::parse(&buf).context("failed to parse inet response header")?;
//         let nlas =
//             SmallVec::<[Nla; 8]>::parse(buf).context("failed to parse inet response NLAs")?;
//         Ok(UnixResponse { header, nlas })
//     }
// }
//
// impl Emitable for UnixResponse {
//     fn buffer_len(&self) -> usize {
//         self.header.buffer_len() + self.nlas.as_slice().buffer_len()
//     }
//
//     fn emit(&self, buffer: &mut [u8]) {
//         self.header.emit(buffer);
//         self.nlas
//             .as_slice()
//             .emit(&mut buffer[self.header.buffer_len()..]);
//     }
// }
