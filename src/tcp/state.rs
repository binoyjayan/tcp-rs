/// A connection progresses through a series of states during its lifetime.
/// The states are: `Closed`, `Listen`, `SynReceived`, `Established`, `FinWait1`,
/// `FinWait2`, `CloseWait`, `Closing`, `LastAck`, `TimeWait`, and the fictional
/// state `Closed`. `Closed` is fictional because it represents the state when
/// there is no TCB, and therefore, no connection. Briefly, the meanings of
/// the states are:
///
/// - `Closed`: Represents the closed state of the connection.
///
/// - `Listen`: Represents waiting for a connection request from any remote
///   TCP and port.
///
/// - `SynReceived`: Represents waiting for a confirming connection
///   request acknowledgment after having both received and sent a
///   connection request.
///
/// - `Established`: Represents an open connection, data received can be
///   delivered to the user. The normal state for the data transfer phase
///   of the connection.
///
/// - `FinWait1`: Represents waiting for a connection termination request
///   from the remote TCP, or an acknowledgment of the connection
///   termination request previously sent.
///
/// - `FinWait2`: Represents waiting for a connection termination request
///   from the remote TCP.
///
/// - `CloseWait`: Represents waiting for a connection termination request
///   from the local user.
///
/// - `Closing`: Represents waiting for a connection termination request
///   acknowledgment from the remote TCP.
///
/// - `LastAck`: Represents waiting for an acknowledgment of the
///   connection termination request previously sent to the remote TCP
///   (which includes an acknowledgment of its connection termination
///   request).
#[derive(Debug, Default)]
pub enum State {
    #[default]
    // Closed,
    // Listen,
    SynReceived,
    Established,
    // FinWait1,
    // FinWait2,
    // CloseWait,
    // Closing,
    // LastAck,
}

impl State {
    pub fn is_sync(&self) -> bool {
        matches!(self, Self::Established)
    }
}
