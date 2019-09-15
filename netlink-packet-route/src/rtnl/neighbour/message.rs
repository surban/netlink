use failure::ResultExt;

use crate::{
    rtnl::{
        neighbour::{Header, MessageBuffer, Nla},
        traits::{Emitable, Parseable},
    },
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Message {
    pub header: Header,
    pub nlas: Vec<Nla>,
}

impl Emitable for Message {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas.as_slice().emit(buffer);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MessageBuffer<&'a T>> for Message {
    fn parse(buf: &MessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Message {
            header: Header::parse(&buf).context("failed to parse neighbour message header")?,
            nlas: Vec::<Nla>::parse(&buf).context("failed to parse neighbour message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MessageBuffer<&'a T>> for Vec<Nla> {
    fn parse(buf: &MessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
