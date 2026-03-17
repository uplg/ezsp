use core::fmt;
use std::error::Error;
use std::fmt::Display;

/// An error that can occur when parsing an APS frame.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ParseApsFrameError {
    /// Invalid message type.
    InvalidMessageType(u8),
    /// The ZDP frame is invalid.
    ParseZdpFrameError(ParseZdpFrameError),
    /// The ZCL frame is invalid.
    ParseZclFrameError(zcl::ParseFrameError),
    /// The profile ID is invalid.
    InvalidProfile(u16),
}

impl Display for ParseApsFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageType(msg_type) => write!(f, "Invalid message type: {msg_type}"),
            Self::ParseZdpFrameError(error) => error.fmt(f),
            Self::ParseZclFrameError(error) => error.fmt(f),
            Self::InvalidProfile(profile) => write!(f, "Invalid profile ID: {profile}"),
        }
    }
}

impl Error for ParseApsFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidMessageType(_) => None,
            Self::ParseZdpFrameError(error) => Some(error),
            Self::ParseZclFrameError(error) => Some(error),
            Self::InvalidProfile(_) => None,
        }
    }
}

/// Errors that can occur when converting an incoming message to a ZDP frame.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ParseZdpFrameError {
    /// The source endpoint is invalid (must be 0 for ZDP commands).
    SourceEndpoint(u8),
    /// The destination endpoint is invalid (must be 0 for ZDP commands).
    DestinationEndpoint(u8),
    /// The cluster ID could not be parsed into a ZDP frame.
    ClusterId(u16),
    /// The ZDP frame is invalid.
    ZdpFrame,
}

impl Display for ParseZdpFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceEndpoint(endpoint) => {
                write!(
                    f,
                    "Source endpoint must be 0 for ZDP commands, got {endpoint}"
                )
            }
            Self::DestinationEndpoint(endpoint) => {
                write!(
                    f,
                    "Destination endpoint must be 0 for ZDP commands, got {endpoint}",
                )
            }
            Self::ClusterId(cluster_id) => {
                write!(f, "Invalid cluster ID for ZDP frame: {cluster_id:#06X}")
            }
            Self::ZdpFrame => write!(f, "Invalid ZDP frame"),
        }
    }
}

impl Error for ParseZdpFrameError {}
