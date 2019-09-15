use super::{MessageBuffer, NSID_HEADER_LEN};
use crate::{
    rtnl::traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub rtgen_family: u8,
}

impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

impl Header {
    /// Create a new `Header`:
    pub fn new() -> Self {
        Header { rtgen_family: 0 }
    }
}

impl Emitable for Header {
    fn buffer_len(&self) -> usize {
        NSID_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = MessageBuffer::new(buffer);
        packet.set_rtgen_family(self.rtgen_family);
    }
}

impl<T: AsRef<[u8]>> Parseable<MessageBuffer<T>> for Header {
    fn parse(buf: &MessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Header {
            rtgen_family: buf.rtgen_family(),
        })
    }
}
