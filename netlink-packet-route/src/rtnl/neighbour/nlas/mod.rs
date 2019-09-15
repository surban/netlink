mod cache_info;
pub use self::cache_info::*;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        nla::{self, DefaultNla, NlaBuffer},
        traits::{Emitable, Parseable},
        utils::{parse_u16, parse_u32},
    },
    DecodeError,
};

pub const NDA_UNSPEC: u16 = 0;
pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;
pub const NDA_CACHEINFO: u16 = 3;
pub const NDA_PROBES: u16 = 4;
pub const NDA_VLAN: u16 = 5;
pub const NDA_PORT: u16 = 6;
pub const NDA_VNI: u16 = 7;
pub const NDA_IFINDEX: u16 = 8;
pub const NDA_MASTER: u16 = 9;
pub const NDA_LINK_NETNSID: u16 = 10;
pub const NDA_SRC_VNI: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    Unspec(Vec<u8>),
    Destination(Vec<u8>),
    LinkLocalAddress(Vec<u8>),
    CacheInfo(CacheInfo),
    Probes(Vec<u8>),
    Vlan(u16),
    Port(Vec<u8>),
    Vni(u32),
    IfIndex(u32),
    Master(Vec<u8>),
    LinkNetNsId(Vec<u8>),
    SourceVni(u32),
    Other(DefaultNla),
}

impl nla::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes)
            | Destination(ref bytes)
            | LinkLocalAddress(ref bytes)
            | Probes(ref bytes)
            | Port(ref bytes)
            | Master(ref bytes)
            | LinkNetNsId(ref bytes) => bytes.len(),
            CacheInfo(_) => NEIGHBOUR_CACHE_INFO_LEN,
            Vlan(_) => 2,
            Vni(_)
            | IfIndex(_)
            | SourceVni(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes)
            | Destination(ref bytes)
            | LinkLocalAddress(ref bytes)
            | Probes(ref bytes)
            | Port(ref bytes)
            | Master(ref bytes)
            | LinkNetNsId(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            CacheInfo(ref cacheinfo) => cacheinfo.emit(buffer),
            Vlan(ref value) => NativeEndian::write_u16(buffer, *value),
            Vni(ref value)
            | IfIndex(ref value)
            | SourceVni(ref value) => NativeEndian::write_u32(buffer, *value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => NDA_UNSPEC,
            Destination(_) => NDA_DST,
            LinkLocalAddress(_) => NDA_LLADDR,
            CacheInfo(_) => NDA_CACHEINFO,
            Probes(_) => NDA_PROBES,
            Vlan(_) => NDA_VLAN,
            Port(_) => NDA_PORT,
            Vni(_) => NDA_VNI,
            IfIndex(_) => NDA_IFINDEX,
            Master(_) => NDA_MASTER,
            LinkNetNsId(_) => NDA_LINK_NETNSID,
            SourceVni(_) => NDA_SRC_VNI,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::Nla::*;

        let payload = buf.value();
        Ok(match buf.kind() {
            NDA_UNSPEC => Unspec(payload.to_vec()),
            NDA_DST => Destination(payload.to_vec()),
            NDA_LLADDR => LinkLocalAddress(payload.to_vec()),
            NDA_CACHEINFO => {
                let buf =
                    CacheInfoBuffer::new_checked(payload).context("invalid NDA_CACHEINFO value")?;
                CacheInfo(
                    cache_info::CacheInfo::parse(&buf).context("invalid NDA_CACHEINFO value")?,
                )
            }
            NDA_PROBES => Probes(payload.to_vec()),
            NDA_VLAN => Vlan(parse_u16(payload)?),
            NDA_PORT => Port(payload.to_vec()),
            NDA_VNI => Vni(parse_u32(payload)?),
            NDA_IFINDEX => IfIndex(parse_u32(payload)?),
            NDA_MASTER => Master(payload.to_vec()),
            NDA_LINK_NETNSID => LinkNetNsId(payload.to_vec()),
            NDA_SRC_VNI => SourceVni(parse_u32(payload)?),
            _ => Other(DefaultNla::parse(buf).context("invalid link NLA value (unknown type)")?),
        })
    }
}
