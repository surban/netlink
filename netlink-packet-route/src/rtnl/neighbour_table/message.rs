use crate::{
    nlas::neighbour_table::Nla,
    traits::{Emitable, Parseable},
    DecodeError, NeighbourTableHeader, NeighbourTableMessageBuffer,
};
use failure::ResultExt;
use smallvec::SmallVec;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NeighbourTableMessage {
    pub header: NeighbourTableHeader,
    pub nlas: SmallVec<[Nla; 4]>,
}

impl Emitable for NeighbourTableMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourTableMessageBuffer<&'a T>>
    for NeighbourTableMessage
{
    fn parse(buf: &NeighbourTableMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(NeighbourTableMessage {
            header: NeighbourTableHeader::parse(buf)
                .context("failed to parse neighbour table message header")?,
            nlas: SmallVec::<[Nla; 4]>::parse(buf)
                .context("failed to parse neighbour table message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourTableMessageBuffer<&'a T>> for SmallVec<[Nla; 4]> {
    fn parse(buf: &NeighbourTableMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = smallvec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
