use crate::{
    nlas::route::Nla,
    traits::{Emitable, Parseable},
    DecodeError, RouteHeader, RouteMessageBuffer,
};
use failure::ResultExt;
use smallvec::SmallVec;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub nlas: SmallVec<[Nla; 4]>,
}

impl Emitable for RouteMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for RouteMessage {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(RouteMessage {
            header: RouteHeader::parse(buf).context("failed to parse route message header")?,
            nlas: SmallVec::<[Nla; 4]>::parse(buf).context("failed to parse route message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for SmallVec<[Nla; 4]> {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = smallvec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
