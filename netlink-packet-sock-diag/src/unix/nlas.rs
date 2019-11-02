use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

pub use crate::utils::nla::{DefaultNla, NlaBuffer, NlasIterator};

use crate::{
    constants::*,
    parsers::{parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

pub enum Nla {
    Name(String),
    Vfs(Vfs),
    Peer(u32),
    PendingConnections(u32),
    QueueLength(QueueLength),
    MemInfo(MemInfo),
    Shutdown(u8),
}

buffer!(VfsBuffer(8) {
    inode: (u32, 0..4),
    device: (u32, 4..8),
});

pub struct Vfs {
    inode: u32,
    device: u32,
}


SK_MEMINFO_RMEM_ALLOC
       The amount of data in receive queue.

SK_MEMINFO_RCVBUF
       The receive socket buffer as set by SO_RCVBUF.

SK_MEMINFO_WMEM_ALLOC
       The amount of data in send queue.

SK_MEMINFO_SNDBUF
       The send socket buffer as set by SO_SNDBUF.

SK_MEMINFO_FWD_ALLOC
       The amount of memory scheduled for future use (TCP only).

SK_MEMINFO_WMEM_QUEUED
       The amount of data queued by TCP, but not yet sent.

SK_MEMINFO_OPTMEM
       The amount of memory allocated for the socket's service needs (e.g., socket filter).

SK_MEMINFO_BACKLOG
       The amount of packets in the backlog (not yet processed).
