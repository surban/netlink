use failure::ResultExt;
use smallvec::SmallVec;

use crate::{
    nlas::neighbour::Nla,
    traits::{Emitable, Parseable},
    DecodeError, NeighbourHeader, NeighbourMessageBuffer,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NeighbourMessage {
    pub header: NeighbourHeader,
    pub nlas: SmallVec<[Nla; 4]>,
}

impl Emitable for NeighbourMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourMessageBuffer<&'a T>> for NeighbourMessage {
    fn parse(buf: &NeighbourMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(NeighbourMessage {
            header: NeighbourHeader::parse(&buf)
                .context("failed to parse neighbour message header")?,
            nlas: SmallVec::<[Nla; 4]>::parse(&buf)
                .context("failed to parse neighbour message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourMessageBuffer<&'a T>> for SmallVec<[Nla; 4]> {
    fn parse(buf: &NeighbourMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = smallvec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
