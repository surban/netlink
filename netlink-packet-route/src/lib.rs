#[macro_use]
pub(crate) extern crate netlink_packet_utils as utils;
pub use self::utils::DecodeError;

pub use netlink_packet_core as netlink;

pub mod rtnl;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
