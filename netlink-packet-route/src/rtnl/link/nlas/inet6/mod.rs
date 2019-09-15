use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        link::nlas::{
            IFLA_INET6_ADDR_GEN_MODE, IFLA_INET6_CACHEINFO, IFLA_INET6_CONF, IFLA_INET6_FLAGS,
            IFLA_INET6_ICMP6STATS, IFLA_INET6_STATS, IFLA_INET6_TOKEN, IFLA_INET6_UNSPEC,
        },
        nla::{DefaultNla, Nla, NlaBuffer},
        traits::{Emitable, Parseable},
        utils::{parse_ipv6, parse_u32, parse_u8},
    },
    DecodeError,
};

mod cache;
pub use self::cache::*;
mod dev_conf;
pub use self::dev_conf::*;
mod icmp6_stats;
pub use self::icmp6_stats::*;
mod stats;
pub use self::stats::*;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Inet6 {
    Flags(u32),
    CacheInfo(Inet6CacheInfo),
    // Inet6DevConf is big (198 bytes), so we're wasting a space for each variant without a box.
    DevConf(Box<Inet6DevConf>),
    Unspec(Vec<u8>),
    // Inet6Stats is huge (288 bytes), so we're wasting a *lot* of space for each variant without a
    // box.
    Stats(Box<Inet6Stats>),
    IcmpStats(Icmp6Stats),
    Token([u8; 16]),
    AddrGenMode(u8),
    Other(DefaultNla),
}

impl Nla for Inet6 {
    fn value_len(&self) -> usize {
        use self::Inet6::*;
        match *self {
            Unspec(ref bytes) => bytes.len(),
            CacheInfo(ref cache_info) => cache_info.buffer_len(),
            DevConf(ref dev_conf) => dev_conf.buffer_len(),
            Stats(ref stats) => stats.buffer_len(),
            IcmpStats(ref icmp_stats) => icmp_stats.buffer_len(),
            Flags(_) => 4,
            Token(_) => 16,
            AddrGenMode(_) => 1,
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Inet6::*;
        match *self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Flags(ref value) => NativeEndian::write_u32(buffer, *value),
            CacheInfo(ref cache_info) => cache_info.emit(buffer),
            DevConf(ref inet6_dev_conf) => inet6_dev_conf.emit(buffer),
            Stats(ref inet6_stats) => inet6_stats.emit(buffer),
            IcmpStats(ref icmp6_stats) => icmp6_stats.emit(buffer),
            Token(ref ipv6) => buffer.copy_from_slice(&ipv6[..]),
            AddrGenMode(value) => buffer[0] = value,
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Inet6::*;
        match *self {
            Unspec(_) => IFLA_INET6_UNSPEC,
            Flags(_) => IFLA_INET6_FLAGS,
            CacheInfo(_) => IFLA_INET6_CACHEINFO,
            DevConf(_) => IFLA_INET6_CONF,
            Stats(_) => IFLA_INET6_STATS,
            IcmpStats(_) => IFLA_INET6_ICMP6STATS,
            Token(_) => IFLA_INET6_TOKEN,
            AddrGenMode(_) => IFLA_INET6_ADDR_GEN_MODE,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Inet6 {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::Inet6::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_INET6_UNSPEC => Unspec(payload.to_vec()),
            IFLA_INET6_FLAGS => {
                Flags(parse_u32(payload).context("invalid IFLA_INET6_FLAGS value")?)
            }
            IFLA_INET6_CACHEINFO => {
                let buf = Inet6CacheInfoBuffer::new_checked(payload)
                    .context("invalid IFLA_INET6_CACHEINFO value")?;
                CacheInfo(
                    Inet6CacheInfo::parse(&buf).context("invalid IFLA_INET6_CACHEINFO value")?,
                )
            }
            IFLA_INET6_CONF => {
                let buf = Inet6DevConfBuffer::new_checked(payload)
                    .context("invalid IFLA_INET6_CONF value")?;
                let parsed = Inet6DevConf::parse(&buf).context("invalid IFLA_INET6_CONF value")?;
                DevConf(Box::new(parsed))
            }
            IFLA_INET6_STATS => {
                let buf = Inet6StatsBuffer::new_checked(payload)
                    .context("invalid IFLA_INET6_STATS value")?;
                let parsed = Inet6Stats::parse(&buf).context("invalid IFLA_INET6_STATS value")?;
                Stats(Box::new(parsed))
            }
            IFLA_INET6_ICMP6STATS => {
                let buf = Icmp6StatsBuffer::new_checked(payload)
                    .context("invalid IFLA_INET6_ICMP6STATS value")?;
                IcmpStats(Icmp6Stats::parse(&buf).context("invalid IFLA_INET6_ICMP6STATS value")?)
            }
            IFLA_INET6_TOKEN => {
                Token(parse_ipv6(payload).context("invalid IFLA_INET6_TOKEN value")?)
            }
            IFLA_INET6_ADDR_GEN_MODE => {
                AddrGenMode(parse_u8(payload).context("invalid IFLA_INET6_ADDR_GEN_MODE value")?)
            }
            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}
