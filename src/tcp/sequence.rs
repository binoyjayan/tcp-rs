/// Send Sequence Space RFC 793 Section 3.2
///
/// Represents the sequence space for sending data.
///
/// Fields:
/// - `iss`: Initial send sequence number.
/// - `una`: The unacknowledged sequence number.
/// - `nxt`: The next sequence number to be sent.
/// - `wnd`: The window size.
/// - `urgent`: Indicates whether urgent data is present.
/// - `wl1`: Sequence number used for the last window update.
/// - `wl2`: Acknowledgment number used for the last window update.
#[derive(Debug, Default)]
pub struct SendSequenceSpace {
    pub iss: u32,
    pub una: u32,
    pub nxt: u32,
    pub wnd: u16,
    pub urgent: u16,
    pub wl1: u32,
    pub wl2: u32,
}

/// Receive Sequence Space RFC 793 Section 3.2
///
/// Represents the sequence space for receiving data.
///
/// Fields:
/// - `irs`: Initial receive sequence number.
/// - `nxt`: The next expected sequence number to receive.
/// - `wnd`: The window size.
/// - `urgent`: Indicates whether urgent data is present.
#[derive(Debug, Default)]
pub struct ReceiveSequenceSpace {
    pub irs: u32,
    pub nxt: u32,
    pub wnd: u16,
    pub urgent: u16,
}
