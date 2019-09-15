mod flags;
pub use self::flags::*;

mod link_layer_type;
pub use self::link_layer_type::*;

use crate::{
    rtnl::{
        link::{MessageBuffer, LINK_HEADER_LEN},
        traits::{Emitable, Parseable},
    },
    DecodeError,
};

/// High level representation of `RTM_GETLINK`, `RTM_SETLINK`, `RTM_NEWLINK` and `RTM_DELLINK`
/// messages headers.
///
/// These headers have the following structure:
///
/// ```no_rust
/// 0                8                16              24               32
/// +----------------+----------------+----------------+----------------+
/// |interface family|    reserved    |         link layer type         |
/// +----------------+----------------+----------------+----------------+
/// |                             link index                            |
/// +----------------+----------------+----------------+----------------+
/// |                               flags                               |
/// +----------------+----------------+----------------+----------------+
/// |                            change mask                            |
/// +----------------+----------------+----------------+----------------+
/// ```
///
/// `Header` exposes all these fields except for the "reserved" one.
///
/// # Example
///
/// ```rust
/// use netlink_packet_route::rtnl::link::{Header, Flags, LayerType, IFF_UP};
/// fn main() {
///     let mut hdr = Header::new();
///     assert_eq!(hdr.interface_family, 0u8);
///     assert_eq!(hdr.link_layer_type, LayerType::Ether);
///     assert_eq!(hdr.flags, Flags::new());
///     assert_eq!(hdr.change_mask, Flags::new());
///
///     let flags = Flags::from(IFF_UP);
///     hdr.flags = flags;
///     hdr.change_mask = flags;
///     hdr.link_layer_type = LayerType::IpGre;
/// }
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub interface_family: u8,
    pub index: u32,
    pub link_layer_type: LayerType,
    pub flags: Flags,
    pub change_mask: Flags,
}

impl Default for Header {
    fn default() -> Self {
        Header::new()
    }
}

impl Header {
    /// Create a new `Header`:
    ///
    /// - interface family defaults to `AF_UNSPEC` (0)
    /// - the link layer type defaults to `ARPHRD_ETHER` ([`LayerType::Ether`](enum.LayerType.html))
    /// - the linx index defaults to 0
    /// - the flags default to 0 ([`Flags::new()`](struct.Flags.html#method.new))
    /// - the change master default to 0 ([`Flags::new()`](struct.Flags.html#method.new))
    pub fn new() -> Self {
        Header {
            interface_family: 0, // AF_UNSPEC
            link_layer_type: LayerType::Ether,
            flags: Flags::new(),
            change_mask: Flags::new(),
            index: 0,
        }
    }
}

impl Emitable for Header {
    fn buffer_len(&self) -> usize {
        LINK_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = MessageBuffer::new(buffer);
        packet.set_interface_family(self.interface_family);
        packet.set_link_index(self.index);
        packet.set_change_mask(self.change_mask.into());
        packet.set_link_layer_type(self.link_layer_type.into());
        packet.set_flags(self.flags.into());
    }
}

impl<T: AsRef<[u8]>> Parseable<MessageBuffer<T>> for Header {
    fn parse(buf: &MessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            interface_family: buf.interface_family(),
            link_layer_type: buf.link_layer_type().into(),
            index: buf.link_index(),
            change_mask: buf.change_mask().into(),
            flags: buf.flags().into(),
        })
    }
}
