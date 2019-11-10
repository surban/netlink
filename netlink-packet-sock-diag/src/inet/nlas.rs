use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

pub use crate::utils::nla::{DefaultNla, NlaBuffer, NlasIterator};

use crate::{
    constants::*,
    parsers::{parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

pub const MEM_INFO_LEN: usize = 16;

buffer!(MemInfoBuffer(MEM_INFO_LEN) {
    rmem: (u32, 0..4),
    wmem: (u32, 4..8),
    fmem: (u32, 8..12),
    tmem: (u32, 12..16)
});

// FIXME: find better names for the fields here. rmem could be
// renamed read_queue, and wmem send_queue, but I have no idea for the
// other two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInfo {
    /// Amount of data in the receive queue.
    pub rmem: u32,
    /// Amount of data that is queued by TCP but not yet sent.
    pub wmem: u32,
    /// Amount of memory scheduled for future use (TCP only).
    pub fmem: u32,
    /// The amount of data in send queue.
    pub tmem: u32,
}

impl<T: AsRef<[u8]>> Parseable<MemInfoBuffer<T>> for MemInfo {
    fn parse(buf: &MemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rmem: buf.rmem(),
            wmem: buf.wmem(),
            fmem: buf.fmem(),
            tmem: buf.tmem(),
        })
    }
}

impl Emitable for MemInfo {
    fn buffer_len(&self) -> usize {
        MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = MemInfoBuffer::new(buf);
        buf.set_rmem(self.rmem);
        buf.set_wmem(self.wmem);
        buf.set_fmem(self.fmem);
        buf.set_tmem(self.tmem);
    }
}

pub const TCP_INFO_LEN: usize = 232;

buffer!(TcpInfoBuffer(TCP_INFO_LEN) {
    state: (u8, 0),
    ca_state: (u8, 1),
    retransmits: (u8, 2),
    probes: (u8, 3),
    backoff: (u8, 4),
    options: (u8, 5),
    wscale: (u8, 6),
    delivery_rate_app_limited: (u8, 7),
    rto: (u32, 8..12),
    ato: (u32, 12..16),
    snd_mss: (u32, 16..20),
    rcv_mss: (u32, 20..24),
    unacked: (u32, 24..28),
    sacked: (u32, 28..32),
    lost: (u32, 32..36),
    retrans: (u32, 36..40),
    fackets: (u32, 40..44),
    last_data_sent: (u32, 44..48),
    last_ack_sent: (u32, 48..52),
    last_data_recv: (u32, 52..56),
    last_ack_recv: (u32, 56..60),
    pmtu: (u32, 60..64),
    rcv_ssthresh: (u32, 64..68),
    rtt: (u32, 68..72),
    rttvar: (u32, 72..76),
    snd_ssthresh: (u32, 76..80),
    snd_cwnd: (u32, 80..84),
    advmss: (u32, 84..88),
    reordering: (u32, 88..92),
    rcv_rtt: (u32, 92..96),
    rcv_space: (u32, 96..100),
    total_retrans: (u32, 100..104),
    pacing_rate: (u64, 104..112),
    max_pacing_rate: (u64, 112..120),
    bytes_acked: (u64, 120..128),
    bytes_received: (u64, 128..136),
    segs_out: (u32, 136..140),
    segs_in: (u32, 140..144),
    notsent_bytes: (u32, 144..148),
    min_rtt: (u32, 148..152),
    data_segs_in: (u32, 152..156),
    data_segs_out: (u32, 156..160),
    delivery_rate: (u64, 160..168),
    busy_time: (u64, 168..176),
    rwnd_limited: (u64, 176..184),
    sndbuf_limited: (u64, 184..192),
    delivered: (u32, 192..196),
    delivered_ce: (u32, 196..200),
    bytes_sent: (u64, 200..208),
    bytes_retrans: (u64, 208..216),
    dsack_dups: (u32,   216..220),
    reord_seen: (u32,   220..224),
    // These are pretty recent addition, we should hide them behing
    // `#[cfg]` flag
    rcv_ooopack: (u32, 224..228),
    snd_wnd: (u32, 228..232),
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInfo {
    pub state: u8,
    pub ca_state: u8,
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    pub wscale: u8,
    pub delivery_rate_app_limited: u8,

    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,

    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub fackets: u32,

    // Times.
    pub last_data_sent: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,

    // Metrics.
    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    pub rtt: u32,
    pub rttvar: u32,
    pub snd_ssthresh: u32,
    pub snd_cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,

    pub rcv_rtt: u32,
    pub rcv_space: u32,

    pub total_retrans: u32,

    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64,    // RFC4898 tcpEStatsAppHCThruOctetsAcked
    pub bytes_received: u64, // RFC4898 tcpEStatsAppHCThruOctetsReceived
    pub segs_out: u32,       // RFC4898 tcpEStatsPerfSegsOut
    pub segs_in: u32,        // RFC4898 tcpEStatsPerfSegsIn

    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,  // RFC4898 tcpEStatsDataSegsIn
    pub data_segs_out: u32, // RFC4898 tcpEStatsDataSegsOut

    pub delivery_rate: u64,

    pub busy_time: u64,      // Time (usec) busy sending data
    pub rwnd_limited: u64,   // Time (usec) limited by receive window
    pub sndbuf_limited: u64, // Time (usec) limited by send buffer

    pub delivered: u32,
    pub delivered_ce: u32,

    pub bytes_sent: u64,    // RFC4898 tcpEStatsPerfHCDataOctetsOut
    pub bytes_retrans: u64, // RFC4898 tcpEStatsPerfOctetsRetrans
    pub dsack_dups: u32,    // RFC4898 tcpEStatsStackDSACKDups
    /// reordering events seen
    pub reord_seen: u32,

    /// Out-of-order packets received
    pub rcv_ooopack: u32,
    /// peer's advertised receive window after scaling (bytes)
    pub snd_wnd: u32,
}

impl<T: AsRef<[u8]>> Parseable<TcpInfoBuffer<T>> for TcpInfo {
    fn parse(buf: &TcpInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            state: buf.state(),
            ca_state: buf.ca_state(),
            retransmits: buf.retransmits(),
            probes: buf.probes(),
            backoff: buf.backoff(),
            options: buf.options(),
            wscale: buf.wscale(),
            delivery_rate_app_limited: buf.delivery_rate_app_limited(),
            rto: buf.rto(),
            ato: buf.ato(),
            snd_mss: buf.snd_mss(),
            rcv_mss: buf.rcv_mss(),
            unacked: buf.unacked(),
            sacked: buf.sacked(),
            lost: buf.lost(),
            retrans: buf.retrans(),
            fackets: buf.fackets(),
            last_data_sent: buf.last_data_sent(),
            last_ack_sent: buf.last_ack_sent(),
            last_data_recv: buf.last_data_recv(),
            last_ack_recv: buf.last_ack_recv(),
            pmtu: buf.pmtu(),
            rcv_ssthresh: buf.rcv_ssthresh(),
            rtt: buf.rtt(),
            rttvar: buf.rttvar(),
            snd_ssthresh: buf.snd_ssthresh(),
            snd_cwnd: buf.snd_cwnd(),
            advmss: buf.advmss(),
            reordering: buf.reordering(),
            rcv_rtt: buf.rcv_rtt(),
            rcv_space: buf.rcv_space(),
            total_retrans: buf.total_retrans(),
            pacing_rate: buf.pacing_rate(),
            max_pacing_rate: buf.max_pacing_rate(),
            bytes_acked: buf.bytes_acked(),
            bytes_received: buf.bytes_received(),
            segs_out: buf.segs_out(),
            segs_in: buf.segs_in(),
            notsent_bytes: buf.notsent_bytes(),
            min_rtt: buf.min_rtt(),
            data_segs_in: buf.data_segs_in(),
            data_segs_out: buf.data_segs_out(),
            delivery_rate: buf.delivery_rate(),
            busy_time: buf.busy_time(),
            rwnd_limited: buf.rwnd_limited(),
            sndbuf_limited: buf.sndbuf_limited(),
            delivered: buf.delivered(),
            delivered_ce: buf.delivered_ce(),
            bytes_sent: buf.bytes_sent(),
            bytes_retrans: buf.bytes_retrans(),
            dsack_dups: buf.dsack_dups(),
            reord_seen: buf.reord_seen(),
            rcv_ooopack: buf.rcv_ooopack(),
            snd_wnd: buf.snd_wnd(),
        })
    }
}

impl Emitable for TcpInfo {
    fn buffer_len(&self) -> usize {
        TCP_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = TcpInfoBuffer::new(buf);
        buf.set_state(self.state);
        buf.set_ca_state(self.ca_state);
        buf.set_retransmits(self.retransmits);
        buf.set_probes(self.probes);
        buf.set_backoff(self.backoff);
        buf.set_options(self.options);
        buf.set_wscale(self.wscale);
        buf.set_delivery_rate_app_limited(self.delivery_rate_app_limited);
        buf.set_rto(self.rto);
        buf.set_ato(self.ato);
        buf.set_snd_mss(self.snd_mss);
        buf.set_rcv_mss(self.rcv_mss);
        buf.set_unacked(self.unacked);
        buf.set_sacked(self.sacked);
        buf.set_lost(self.lost);
        buf.set_retrans(self.retrans);
        buf.set_fackets(self.fackets);
        buf.set_last_data_sent(self.last_data_sent);
        buf.set_last_ack_sent(self.last_ack_sent);
        buf.set_last_data_recv(self.last_data_recv);
        buf.set_last_ack_recv(self.last_ack_recv);
        buf.set_pmtu(self.pmtu);
        buf.set_rcv_ssthresh(self.rcv_ssthresh);
        buf.set_rtt(self.rtt);
        buf.set_rttvar(self.rttvar);
        buf.set_snd_ssthresh(self.snd_ssthresh);
        buf.set_snd_cwnd(self.snd_cwnd);
        buf.set_advmss(self.advmss);
        buf.set_reordering(self.reordering);
        buf.set_rcv_rtt(self.rcv_rtt);
        buf.set_rcv_space(self.rcv_space);
        buf.set_total_retrans(self.total_retrans);
        buf.set_pacing_rate(self.pacing_rate);
        buf.set_max_pacing_rate(self.max_pacing_rate);
        buf.set_bytes_acked(self.bytes_acked);
        buf.set_bytes_received(self.bytes_received);
        buf.set_segs_out(self.segs_out);
        buf.set_segs_in(self.segs_in);
        buf.set_notsent_bytes(self.notsent_bytes);
        buf.set_min_rtt(self.min_rtt);
        buf.set_data_segs_in(self.data_segs_in);
        buf.set_data_segs_out(self.data_segs_out);
        buf.set_delivery_rate(self.delivery_rate);
        buf.set_busy_time(self.busy_time);
        buf.set_rwnd_limited(self.rwnd_limited);
        buf.set_sndbuf_limited(self.sndbuf_limited);
        buf.set_delivered(self.delivered);
        buf.set_delivered_ce(self.delivered_ce);
        buf.set_bytes_sent(self.bytes_sent);
        buf.set_bytes_retrans(self.bytes_retrans);
        buf.set_dsack_dups(self.dsack_dups);
        buf.set_reord_seen(self.reord_seen);
        buf.set_rcv_ooopack(self.rcv_ooopack);
        buf.set_snd_wnd(self.snd_wnd);
    }
}

pub const SK_MEM_INFO_LEN: usize = 36;

buffer!(SkMemInfoBuffer(SK_MEM_INFO_LEN) {
    rmem_alloc: (u32, 0..4),
    recvbuf: (u32, 4..8),
    wmem_alloc: (u32, 8..12),
    sndbuf: (u32, 12..16),
    fwd_alloc: (u32, 16..20),
    wmem_queued: (u32, 20..24),
    optmem: (u32, 24..28),
    backlog: (u32, 28..32),
    drops: (u32, 32..36),
});

/// Socket memory information. To understand this information, one
/// must understand how the memory allocated for the send and receive
/// queues of a socket is managed.
///
/// # Warning
///
/// This data structure is not well documented. The explanations given
/// here are the results of my personal research on this topic, but I
/// am by no mean an expert in Linux networking, so take this
/// documentation with a huge grain of salt. Please report any error
/// you may notice. Here are the references I used:
///
/// - https://wiki.linuxfoundation.org/networking/sk_buff
/// - http://vger.kernel.org/~davem/skb_data.html
/// - https://www.coverfire.com/articles/queueing-in-the-linux-network-stack/
/// - https://www.cl.cam.ac.uk/~pes20/Netsem/linuxnet.pdf
///
/// # Linux networking in a nutshell
///
/// The data structure that represents a socket in the kernel,
/// (`sock`) holds a `receive_queue` and `send_queue`, which are
/// effectively linked lists of buffers (`sk_buff`). These buffers
/// hold the actual network data.
///
/// The queues are sometimes referred to as receive and send
/// _buffers_, because they are implemented as first in first out
/// (FIFO) ring buffers. To avoid confusion, we'll stick to the term
/// _queue_.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SkMemInfo {
    /// Number of bytes committed (i.e. actually in use) in the
    /// receive queue. In other words, this is the amount of memory
    /// currently allocated for the receive queue.
    pub receive_queue_allocated: u32,
    /// Maximum amount of memory (in bytes) that can be allocated for
    /// this socket's receive queue. This is set by `SO_RCVBUF`. This
    /// is _not_ the amount of memory currently allocated.
    pub receive_queue_max: u32,
    /// Number of bytes committed (i.e. actually in use) in the send
    /// queue. In other words, this is the amount of memory currently
    /// allocated for the send queue.
    pub send_queue_allocated: u32,
    /// Maximum amount of memory (in bytes) that can be allocated for
    /// this socket's send queue. This is set by `SO_SNDBUF`. This
    /// is _not_ the amount of memory currently allocated.
    pub sndbuf: u32,
    /// The amount of memory scheduled for future use (TCP only).
    pub fwd_alloc: u32,
    /// The amount of data queued by TCP, but not yet sent.
    // http://lkml.iu.edu/hypermail/linux/kernel/0607.3/0207.html
    pub wmem_queued: u32,
    /// The amount of memory allocated for the socket's service needs (e.g., socket filter).
    pub optmem: u32,
    /// The amount of packets in the backlog (not yet processed).
    pub backlog: u32,
    /// The amount of packets was dropped.
    pub drops: u32,
}

impl<T: AsRef<[u8]>> Parseable<SkMemInfoBuffer<T>> for SkMemInfo {
    fn parse(buf: &SkMemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rmem_alloc: buf.rmem_alloc(),
            recvbuf: buf.recvbuf(),
            wmem_alloc: buf.wmem_alloc(),
            sndbuf: buf.sndbuf(),
            fwd_alloc: buf.fwd_alloc(),
            wmem_queued: buf.wmem_queued(),
            optmem: buf.optmem(),
            backlog: buf.backlog(),
            drops: buf.drops(),
        })
    }
}

impl Emitable for SkMemInfo {
    fn buffer_len(&self) -> usize {
        MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = SkMemInfoBuffer::new(buf);
        buf.set_rmem_alloc(self.rmem_alloc);
        buf.set_recvbuf(self.recvbuf);
        buf.set_wmem_alloc(self.wmem_alloc);
        buf.set_sndbuf(self.sndbuf);
        buf.set_fwd_alloc(self.fwd_alloc);
        buf.set_wmem_queued(self.wmem_queued);
        buf.set_optmem(self.optmem);
        buf.set_backlog(self.backlog);
        buf.set_drops(self.drops);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    /// The memory information of the socket. This attribute is
    /// similar to `Nla::SkMemInfo` but provides less information. On
    /// recent kernels, `Nla::SkMemInfo` is used instead.
    // ref: https://patchwork.ozlabs.org/patch/154816/
    MemInfo(MemInfo),
    /// the TCP information
    Info(Box<TcpInfo>),
    /// the congestion control algorithm used
    Congestion(String),
    /// the TOS of the socket.
    Tos(u8),
    /// the traffic class of the socket.
    Tc(u8),
    /// The memory information of the socket
    SkMemInfo(SkMemInfo),
    /// shutdown states
    Shutdown(u8),
    /// The protocol
    Protocol(u8),
    /// Whether the socket is IPv6 only
    SkV6Only(bool),
    /// The mark of the socket.
    Mark(u32),
    /// The class ID of the socket.
    ClassId(u32),
    /// other attribute
    Other(DefaultNla),
}

impl crate::utils::nla::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            MemInfo(_) => MEM_INFO_LEN,
            Info(_) => TCP_INFO_LEN,
            // +1 because we need to append a null byte
            Congestion(ref s) => s.as_bytes().len() + 1,
            Tos(_) | Tc(_) | Shutdown(_) | Protocol(_) | SkV6Only(_) => 1,
            SkMemInfo(_) => SK_MEM_INFO_LEN,
            Mark(_) | ClassId(_) => 4,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            MemInfo(ref value) => value.emit(buffer),
            Info(ref value) => value.emit(buffer),
            Congestion(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Tos(b) | Tc(b) | Shutdown(b) | Protocol(b) => buffer[0] = b,
            SkV6Only(value) => buffer[0] = value.into(),
            SkMemInfo(ref value) => value.emit(buffer),
            Mark(value) | ClassId(value) => NativeEndian::write_u32(buffer, value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            MemInfo(_) => INET_DIAG_MEMINFO,
            Info(_) => INET_DIAG_INFO,
            Congestion(_) => INET_DIAG_CONG,
            Tos(_) => INET_DIAG_TOS,
            Tc(_) => INET_DIAG_TCLASS,
            SkMemInfo(_) => INET_DIAG_SKMEMINFO,
            Shutdown(_) => INET_DIAG_SHUTDOWN,
            Protocol(_) => INET_DIAG_PROTOCOL,
            SkV6Only(_) => INET_DIAG_SKV6ONLY,
            Mark(_) => INET_DIAG_MARK,
            ClassId(_) => INET_DIAG_CLASS_ID,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            INET_DIAG_MEMINFO => {
                let err = "invalid INET_DIAG_MEMINFO value";
                let buf = MemInfoBuffer::new_checked(payload).context(err)?;
                Self::MemInfo(MemInfo::parse(&buf).context(err)?)
            }
            INET_DIAG_INFO => {
                let err = "invalid INET_DIAG_INFO value";
                let buf = TcpInfoBuffer::new_checked(payload).context(err)?;
                Self::Info(Box::new(TcpInfo::parse(&buf).context(err)?))
            }
            INET_DIAG_CONG => {
                Self::Congestion(parse_string(payload).context("invalid INET_DIAG_CONG value")?)
            }
            INET_DIAG_TOS => Self::Tos(parse_u8(payload).context("invalid INET_DIAG_TOS value")?),
            INET_DIAG_TCLASS => {
                Self::Tc(parse_u8(payload).context("invalid INET_DIAG_TCLASS value")?)
            }
            INET_DIAG_SKMEMINFO => {
                let err = "invalid INET_DIAG_SKMEMINFO value";
                let buf = SkMemInfoBuffer::new_checked(payload).context(err)?;
                Self::SkMemInfo(SkMemInfo::parse(&buf).context(err)?)
            }
            INET_DIAG_SHUTDOWN => {
                Self::Shutdown(parse_u8(payload).context("invalid INET_DIAG_SHUTDOWN value")?)
            }
            INET_DIAG_PROTOCOL => {
                Self::Protocol(parse_u8(payload).context("invalid INET_DIAG_PROTOCOL value")?)
            }
            INET_DIAG_SKV6ONLY => {
                Self::SkV6Only(parse_u8(payload).context("invalid INET_DIAG_SKV6ONLY value")? != 0)
            }
            INET_DIAG_MARK => {
                Self::Mark(parse_u32(payload).context("invalid INET_DIAG_MARK value")?)
            }
            INET_DIAG_CLASS_ID => {
                Self::ClassId(parse_u32(payload).context("invalid INET_DIAG_CLASS_ID value")?)
            }
            kind => {
                Self::Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?)
            }
        })
    }
}
