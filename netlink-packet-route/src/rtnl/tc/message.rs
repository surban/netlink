use failure::ResultExt;

use crate::{
    rtnl::{
        tc::{nlas::Nla, MessageBuffer, HEADER_LEN},
        traits::{Emitable, Parseable},
    },
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Message {
    pub header: Header,
    pub nlas: Vec<Nla>,
}

impl Message {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn into_parts(self) -> (Header, Vec<Nla>) {
        (self.header, self.nlas)
    }

    pub fn from_parts(header: Header, nlas: Vec<Nla>) -> Self {
        Message { header, nlas }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    family: u8,
    // Interface index
    index: i32,
    // Qdisc handle
    handle: u32,
    // Parent Qdisc
    parent: u32,
    info: u32,
}

impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

impl Header {
    pub fn new() -> Self {
        Header {
            family: 0,
            index: 0,
            handle: 0,
            parent: 0,
            info: 0,
        }
    }
}

impl Emitable for Header {
    fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = MessageBuffer::new(buffer);
        packet.set_family(self.family);
        packet.set_index(self.index);
        packet.set_handle(self.handle);
        packet.set_parent(self.parent);
        packet.set_info(self.info);
    }
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

impl<T: AsRef<[u8]>> Parseable<MessageBuffer<T>> for Header {
    fn parse(buf: &MessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            family: buf.family(),
            index: buf.index(),
            handle: buf.handle(),
            parent: buf.parent(),
            info: buf.info(),
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MessageBuffer<&'a T>> for Message {
    fn parse(buf: &MessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: Header::parse(buf).context("failed to parse tc message header")?,
            nlas: Vec::<Nla>::parse(buf).context("failed to parse tc message NLAs")?,
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
