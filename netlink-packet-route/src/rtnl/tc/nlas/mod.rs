mod stats;
pub use self::stats::*;

mod stats_queue;
pub use self::stats_queue::*;

mod stats_basic;
pub use self::stats_basic::*;

use std::mem::size_of;

use crate::{
    rtnl::{
        nla::{self, DefaultNla, NlaBuffer, NlasIterator},
        traits::{Emitable, Parseable},
        utils::{parse_string, parse_u8},
    },
    DecodeError,
};

pub const TCA_UNSPEC: u16 = 0;
pub const TCA_KIND: u16 = 1;
pub const TCA_OPTIONS: u16 = 2;
pub const TCA_STATS: u16 = 3;
pub const TCA_XSTATS: u16 = 4;
pub const TCA_RATE: u16 = 5;
pub const TCA_FCNT: u16 = 6;
pub const TCA_STATS2: u16 = 7;
pub const TCA_STAB: u16 = 8;
pub const TCA_PAD: u16 = 9;
pub const TCA_DUMP_INVISIBLE: u16 = 10;
pub const TCA_CHAIN: u16 = 11;
pub const TCA_HW_OFFLOAD: u16 = 12;
pub const TCA_INGRESS_BLOCK: u16 = 13;
pub const TCA_EGRESS_BLOCK: u16 = 14;

pub const TCA_STATS_UNSPEC: u16 = 0;
pub const TCA_STATS_BASIC: u16 = 1;
pub const TCA_STATS_RATE_EST: u16 = 2;
pub const TCA_STATS_QUEUE: u16 = 3;
pub const TCA_STATS_APP: u16 = 4;
pub const TCA_STATS_RATE_EST64: u16 = 5;
pub const TCA_STATS_PAD: u16 = 6;
pub const TCA_STATS_BASIC_HW: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    /// Unspecified
    Unspec(Vec<u8>),
    /// Name of queueing discipline
    Kind(String),
    /// Qdisc-specific options follow
    Options(Vec<u8>),
    /// Qdisc statistics
    Stats(Stats),
    /// Module-specific statistics
    XStats(Vec<u8>),
    /// Rate limit
    Rate(Vec<u8>),
    Fcnt(Vec<u8>),
    Stats2(Vec<Stats2>),
    Stab(Vec<u8>),
    HwOffload(u8),
    Other(DefaultNla),
}

impl nla::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Options(ref bytes)
                | XStats(ref bytes)
                | Rate(ref bytes)
                | Fcnt(ref bytes)
                | Stab(ref bytes) => bytes.len(),
            HwOffload(_) => size_of::<u8>(),
            Stats2(ref thing) => thing.as_slice().buffer_len(),
            Stats(_) => STATS_LEN,
            Kind(ref string) => string.as_bytes().len() + 1,

            // Defaults
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[cfg_attr(nightly, rustfmt::skip)]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Options(ref bytes)
                | XStats(ref bytes)
                | Rate(ref bytes)
                | Fcnt(ref bytes)
                | Stab(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            HwOffload(ref val) => buffer[0] = *val,
            Stats2(ref stats) => stats.as_slice().emit(buffer),
            Stats(ref stats) => stats.emit(buffer),

            Kind(ref string) => {
                buffer.copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }

            // Default
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => TCA_UNSPEC,
            Kind(_) => TCA_KIND,
            Options(_) => TCA_OPTIONS,
            Stats(_) => TCA_STATS,
            XStats(_) => TCA_XSTATS,
            Rate(_) => TCA_RATE,
            Fcnt(_) => TCA_FCNT,
            Stats2(_) => TCA_STATS2,
            Stab(_) => TCA_STAB,
            HwOffload(_) => TCA_HW_OFFLOAD,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_UNSPEC => Self::Unspec(payload.to_vec()),
            TCA_KIND => Self::Kind(parse_string(payload)?),
            TCA_OPTIONS => Self::Options(payload.to_vec()),
            TCA_STATS => Self::Stats(Stats::parse(&StatsBuffer::new_checked(payload)?)?),
            TCA_XSTATS => Self::XStats(payload.to_vec()),
            TCA_RATE => Self::Rate(payload.to_vec()),
            TCA_FCNT => Self::Fcnt(payload.to_vec()),
            TCA_STATS2 => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    nlas.push(Stats2::parse(&(nla?))?);
                }
                Self::Stats2(nlas)
            }
            TCA_STAB => Self::Stab(payload.to_vec()),
            TCA_HW_OFFLOAD => Self::HwOffload(parse_u8(payload)?),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stats2 {
    StatsApp(Vec<u8>),
    StatsBasic(StatsBasic),
    StatsQueue(StatsQueue),
    Other(DefaultNla),
}

impl nla::Nla for Stats2 {
    fn value_len(&self) -> usize {
        use self::Stats2::*;
        match *self {
            StatsApp(ref bytes) => bytes.len(),
            StatsBasic(_) => STATS_BASIC_LEN,
            StatsQueue(_) => STATS_QUEUE_LEN,
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Stats2::*;
        match *self {
            StatsApp(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            StatsBasic(ref nla) => nla.emit(buffer),
            StatsQueue(ref nla) => nla.emit(buffer),
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Stats2::*;
        match *self {
            StatsApp(_) => TCA_STATS_APP,
            StatsBasic(_) => TCA_STATS_BASIC,
            StatsQueue(_) => TCA_STATS_QUEUE,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Stats2 {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_STATS_APP => Self::StatsApp(payload.to_vec()),
            TCA_STATS_BASIC => {
                let buf = StatsBasicBuffer::new_checked(payload)?;
                Self::StatsBasic(StatsBasic::parse(&buf)?)
            }
            TCA_STATS_QUEUE => {
                let buf = StatsQueueBuffer::new_checked(payload)?;
                Self::StatsQueue(StatsQueue::parse(&buf)?)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
