use tokio::sync::oneshot::Sender;

use crate::ember::Status;
use crate::parameters::networking::handler::{EnergyScanResult, NetworkFound};
use crate::{Callback, Error};

/// Messages exchanged with the NCP event handler.
///
/// The event handler receives raw EZSP callbacks, managed scan requests, legacy
/// scan registrations, outgoing message-confirmation registrations, and a termination
/// signal used by [`Ncp::terminate`](crate::Ncp::terminate).
#[derive(Debug)]
pub enum Message {
    /// An incoming callback.
    Callback(Box<Callback>),

    /// Registers a receiver for an active scan issued separately by the caller.
    ///
    /// A failed completion closes this legacy channel. Prefer
    /// [`Self::StartNetworkScan`] for command ownership and explicit errors.
    NetworkScan(Sender<Vec<NetworkFound>>),

    /// Registers a receiver for an energy scan issued separately by the caller.
    ///
    /// A failed completion closes this legacy channel. Prefer
    /// [`Self::StartChannelScan`] for command ownership and explicit errors.
    ChannelScan(Sender<Vec<EnergyScanResult>>),

    /// Starts an active scan and returns its results or command/completion error.
    StartNetworkScan {
        /// Bit mask of channels to scan.
        channel_mask: u32,
        /// EZSP scan duration exponent.
        duration: u8,
        /// Receives the completed scan or its error.
        response: Sender<Result<Vec<NetworkFound>, Error>>,
    },

    /// Starts an energy scan and returns its results or command/completion error.
    StartChannelScan {
        /// Bit mask of channels to scan.
        channel_mask: u32,
        /// EZSP scan duration exponent.
        duration: u8,
        /// Receives the completed scan or its error.
        response: Sender<Result<Vec<EnergyScanResult>, Error>>,
    },

    /// Registers a receiver for a non-final fragment's `messageSent` callback.
    ///
    /// The tag is the internal EZSP representation of the application-provided
    /// APS sequence.
    Sent {
        /// The message tag.
        tag: u8,
        /// The result sender for the stack status reported by `messageSent`.
        sender: Sender<Result<Status, u8>>,
    },

    /// Stops the event handler.
    Terminate,
}

impl From<Box<Callback>> for Message {
    fn from(callback: Box<Callback>) -> Self {
        Self::Callback(callback)
    }
}

impl From<Callback> for Message {
    fn from(callback: Callback) -> Self {
        Self::from(Box::new(callback))
    }
}

impl From<Sender<Vec<NetworkFound>>> for Message {
    fn from(sender: Sender<Vec<NetworkFound>>) -> Self {
        Self::NetworkScan(sender)
    }
}

impl From<Sender<Vec<EnergyScanResult>>> for Message {
    fn from(sender: Sender<Vec<EnergyScanResult>>) -> Self {
        Self::ChannelScan(sender)
    }
}
