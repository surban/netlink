use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

use super::buffer::{MessageBuffer, HEADER_LEN};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub family: u8,
}

impl<T: AsRef<[u8]>> Parseable<MessageBuffer<T>> for Header {
    fn parse(buf: &MessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            family: buf.family(),
        })
    }
}

impl Emitable for Header {
    fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = MessageBuffer::new(buffer);
        packet.set_family(self.family);
    }
}
