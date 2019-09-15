mod config;
pub use config::*;

mod stats;
pub use stats::*;

use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{
    rtnl::{
        nla::{self, DefaultNla, NlaBuffer},
        traits::{Emitable, Parseable},
        utils::{parse_string, parse_u32, parse_u64},
    },
    DecodeError,
};

pub const NDTA_UNSPEC: u16 = 0;
pub const NDTA_NAME: u16 = 1;
pub const NDTA_THRESH1: u16 = 2;
pub const NDTA_THRESH2: u16 = 3;
pub const NDTA_THRESH3: u16 = 4;
pub const NDTA_CONFIG: u16 = 5;
pub const NDTA_PARMS: u16 = 6;
pub const NDTA_STATS: u16 = 7;
pub const NDTA_GC_INTERVAL: u16 = 8;
pub const NDTA_PAD: u16 = 9;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    Unspec(Vec<u8>),
    // FIXME: parse this nla
    Parms(Vec<u8>),
    Name(String),
    Threshold1(u32),
    Threshold2(u32),
    Threshold3(u32),
    Config(Config),
    Stats(Stats),
    GcInterval(u64),
    Other(DefaultNla),
}

impl nla::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) => bytes.len(),
            // strings: +1 because we need to append a nul byte
            Name(ref s) => s.len() + 1,
            Threshold1(_) | Threshold2(_) | Threshold3(_) => 4,
            GcInterval(_) => 8,
            Config(_) => CONFIG_LEN,
            Stats(_) => STATS_LEN,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes) | Parms(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Name(ref string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Config(ref config) => config.emit(buffer),
            Stats(ref stats) => stats.emit(buffer),
            GcInterval(ref value) => NativeEndian::write_u64(buffer, *value),
            Threshold1(ref value) | Threshold2(ref value) | Threshold3(ref value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => NDTA_UNSPEC,
            Name(_) => NDTA_NAME,
            Config(_) => NDTA_CONFIG,
            Stats(_) => NDTA_STATS,
            Parms(_) => NDTA_PARMS,
            GcInterval(_) => NDTA_GC_INTERVAL,
            Threshold1(_) => NDTA_THRESH1,
            Threshold2(_) => NDTA_THRESH2,
            Threshold3(_) => NDTA_THRESH3,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::Nla::*;

        let payload = buf.value();
        Ok(match buf.kind() {
            NDTA_UNSPEC => Unspec(payload.to_vec()),
            NDTA_NAME => Name(parse_string(payload).context("invalid NDTA_NAME value")?),
            NDTA_CONFIG => {
                let buf =
                    ConfigBuffer::new_checked(payload).context("invalid NDTA_CONFIG value")?;
                Config(config::Config::parse(&buf).context("invalid NDTA_CONFIG value")?)
            }
            NDTA_STATS => {
                let buf = StatsBuffer::new_checked(payload).context("invalid NDTA_STATS value")?;
                Stats(stats::Stats::parse(&buf).context("invalid NDTA_STATS value")?)
            }
            NDTA_PARMS => Parms(payload.to_vec()),
            NDTA_GC_INTERVAL => {
                GcInterval(parse_u64(payload).context("invalid NDTA_GC_INTERVAL value")?)
            }
            NDTA_THRESH1 => Threshold1(parse_u32(payload).context("invalid NDTA_THRESH1 value")?),
            NDTA_THRESH2 => Threshold2(parse_u32(payload).context("invalid NDTA_THRESH2 value")?),
            NDTA_THRESH3 => Threshold3(parse_u32(payload).context("invalid NDTA_THRESH3 value")?),
            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}
