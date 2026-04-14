use le_stream::FromLeStream;
use log::warn;

use crate::error::Decode;
use crate::frame::disambiguation::Disambiguation;
use crate::frame::Parameter;
use crate::parameters::{
    binding, bootloader, cbke, green_power, messaging, mfglib, networking, security, trust_center,
    utilities, zll,
};
use crate::Callback;

/// Extension trait that wraps [`FromLeStream::from_le_stream_exact`] with
/// tolerance for unexpected trailing bytes.
///
/// Some NCP firmware versions (or protocol revisions) return additional bytes
/// that our structs do not model.  Rather than treating these as fatal decode
/// errors we log a warning and return the successfully parsed value.
pub(crate) trait FromLeStreamTolerant: FromLeStream + Sized {
    /// Like [`FromLeStream::from_le_stream_exact`], but when the stream still
    /// has bytes remaining after the value has been fully parsed, the extra
    /// bytes are silently discarded (with a warning log) instead of producing
    /// an error.
    fn from_le_stream_tolerant<S: Iterator<Item = u8>>(stream: S) -> Result<Self, Decode> {
        match Self::from_le_stream_exact(stream) {
            Ok(value) => Ok(value),
            Err(le_stream::Error::StreamNotExhausted {
                instance,
                next_byte,
            }) => {
                warn!(
                    "EZSP frame had unexpected trailing bytes (next: {next_byte:#04X}); \
                     parsed value accepted, extra data discarded"
                );
                Ok(instance)
            }
            Err(le_stream::Error::UnexpectedEndOfStream) => Err(Decode::TooFewBytes),
        }
    }
}

impl<T: FromLeStream> FromLeStreamTolerant for T {}

/// A trait for parsing parameters from a little-endian stream given their frame ID.
pub trait Parsable: Sized {
    /// Parse a parameter from a little-endian stream given its frame ID.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`](crate::error::Error) if the parsing of the parameter failed.
    fn parse_from_le_stream<T>(
        id: u16,
        disambiguation: Disambiguation,
        stream: T,
    ) -> Result<Self, Decode>
    where
        T: Iterator<Item = u8>;
}

impl<T> Parsable for T
where
    T: Parameter + FromLeStream,
{
    fn parse_from_le_stream<S>(
        id: u16,
        disambiguation: Disambiguation,
        stream: S,
    ) -> Result<Self, Decode>
    where
        S: Iterator<Item = u8>,
    {
        if Self::ID != id && Self::DISAMBIGUATION != disambiguation {
            return Err(Decode::FrameIdMismatch {
                expected: Self::ID,
                found: id,
            });
        }

        Ok(Self::from_le_stream_tolerant(stream)?)
    }
}

impl Parsable for Callback {
    /// Parse a handler from a little-endian stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame ID is not recognized.
    #[expect(clippy::too_many_lines)]
    fn parse_from_le_stream<T>(id: u16, _: Disambiguation, stream: T) -> Result<Self, Decode>
    where
        T: Iterator<Item = u8>,
    {
        match id {
            // Binding callbacks.
            binding::handler::RemoteDeleteBinding::ID => Ok(Self::Binding(
                binding::handler::Handler::RemoteDeleteBinding(
                    binding::handler::RemoteDeleteBinding::from_le_stream_tolerant(stream)?,
                ),
            )),
            binding::handler::RemoteSetBinding::ID => {
                Ok(Self::Binding(binding::handler::Handler::RemoteSetBinding(
                    binding::handler::RemoteSetBinding::from_le_stream_tolerant(stream)?.into(),
                )))
            }
            // Bootloader callbacks.
            bootloader::handler::BootloadTransmitComplete::ID => Ok(Self::Bootloader(
                bootloader::handler::Handler::BootloadTransmitComplete(
                    bootloader::handler::BootloadTransmitComplete::from_le_stream_tolerant(stream)?,
                ),
            )),
            bootloader::handler::IncomingBootloadMessage::ID => Ok(Self::Bootloader(
                bootloader::handler::Handler::IncomingBootloadMessage(
                    bootloader::handler::IncomingBootloadMessage::from_le_stream_tolerant(stream)?,
                ),
            )),
            // Certificate-based key exchange callbacks.
            cbke::handler::CalculateSmacs::ID => {
                Ok(Self::Cbke(cbke::handler::Handler::CalculateSmacs(
                    cbke::handler::CalculateSmacs::from_le_stream_tolerant(stream)?,
                )))
            }
            cbke::handler::CalculateSmacs283k1::ID => {
                Ok(Self::Cbke(cbke::handler::Handler::CalculateSmacs283k1(
                    cbke::handler::CalculateSmacs283k1::from_le_stream_tolerant(stream)?,
                )))
            }
            cbke::handler::DsaSign::ID => Ok(Self::Cbke(cbke::handler::Handler::DsaSign(
                cbke::handler::DsaSign::from_le_stream_tolerant(stream)?.into(),
            ))),
            cbke::handler::DsaVerify::ID => Ok(Self::Cbke(cbke::handler::Handler::DsaVerify(
                cbke::handler::DsaVerify::from_le_stream_tolerant(stream)?,
            ))),
            cbke::handler::GenerateCbkeKeys::ID => {
                Ok(Self::Cbke(cbke::handler::Handler::GenerateCbkeKeys(
                    cbke::handler::GenerateCbkeKeys::from_le_stream_tolerant(stream)?,
                )))
            }
            cbke::handler::GenerateCbkeKeys283k1::ID => {
                Ok(Self::Cbke(cbke::handler::Handler::GenerateCbkeKeys283k1(
                    cbke::handler::GenerateCbkeKeys283k1::from_le_stream_tolerant(stream)?,
                )))
            }
            // Green Power callbacks.
            green_power::handler::IncomingMessage::ID => Ok(Self::GreenPower(
                green_power::handler::Handler::IncomingMessage(
                    green_power::handler::IncomingMessage::from_le_stream_tolerant(stream)?,
                ),
            )),
            green_power::handler::Sent::ID => {
                Ok(Self::GreenPower(green_power::handler::Handler::Sent(
                    green_power::handler::Sent::from_le_stream_tolerant(stream)?,
                )))
            }
            // Messaging callbacks.
            messaging::handler::IdConflict::ID => {
                Ok(Self::Messaging(messaging::handler::Handler::IdConflict(
                    messaging::handler::IdConflict::from_le_stream_tolerant(stream)?,
                )))
            }
            messaging::handler::IncomingManyToOneRouteRequest::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingManyToOneRouteRequest(
                    messaging::handler::IncomingManyToOneRouteRequest::from_le_stream_tolerant(
                        stream,
                    )?,
                ),
            )),
            messaging::handler::IncomingMessage::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingMessage(
                    messaging::handler::IncomingMessage::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::IncomingNetworkStatus::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingNetworkStatus(
                    messaging::handler::IncomingNetworkStatus::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::IncomingRouteError::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingRouteError(
                    messaging::handler::IncomingRouteError::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::IncomingRouteRecord::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingRouteRecord(
                    messaging::handler::IncomingRouteRecord::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::IncomingSenderEui64::ID => Ok(Self::Messaging(
                messaging::handler::Handler::IncomingSenderEui64(
                    messaging::handler::IncomingSenderEui64::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::MacFilterMatchMessage::ID => Ok(Self::Messaging(
                messaging::handler::Handler::MacFilterMatchMessage(
                    messaging::handler::MacFilterMatchMessage::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::MacPassthroughMessage::ID => Ok(Self::Messaging(
                messaging::handler::Handler::MacPassthroughMessage(
                    messaging::handler::MacPassthroughMessage::from_le_stream_tolerant(stream)?,
                ),
            )),
            messaging::handler::MessageSent::ID => {
                Ok(Self::Messaging(messaging::handler::Handler::MessageSent(
                    messaging::handler::MessageSent::from_le_stream_tolerant(stream)?,
                )))
            }
            messaging::handler::Poll::ID => Ok(Self::Messaging(messaging::handler::Handler::Poll(
                messaging::handler::Poll::from_le_stream_tolerant(stream)?,
            ))),
            messaging::handler::PollComplete::ID => {
                Ok(Self::Messaging(messaging::handler::Handler::PollComplete(
                    messaging::handler::PollComplete::from_le_stream_tolerant(stream)?,
                )))
            }
            messaging::handler::RawTransmitComplete::ID => Ok(Self::Messaging(
                messaging::handler::Handler::RawTransmitComplete(
                    messaging::handler::RawTransmitComplete::from_le_stream_tolerant(stream)?,
                ),
            )),
            // MfgLib callbacks.
            mfglib::handler::Rx::ID => Ok(Self::MfgLib(mfglib::handler::Handler::Rx(
                mfglib::handler::Rx::from_le_stream_tolerant(stream)?,
            ))),
            // Networking callbacks.
            networking::handler::ChildJoin::ID => {
                Ok(Self::Networking(networking::handler::Handler::ChildJoin(
                    networking::handler::ChildJoin::from_le_stream_tolerant(stream)?,
                )))
            }
            networking::handler::DutyCycle::ID => {
                Ok(Self::Networking(networking::handler::Handler::DutyCycle(
                    networking::handler::DutyCycle::from_le_stream_tolerant(stream)?,
                )))
            }
            networking::handler::EnergyScanResult::ID => Ok(Self::Networking(
                networking::handler::Handler::EnergyScanResult(
                    networking::handler::EnergyScanResult::from_le_stream_tolerant(stream)?,
                ),
            )),
            networking::handler::NetworkFound::ID => Ok(Self::Networking(
                networking::handler::Handler::NetworkFound(
                    networking::handler::NetworkFound::from_le_stream_tolerant(stream)?,
                ),
            )),
            networking::handler::ScanComplete::ID => Ok(Self::Networking(
                networking::handler::Handler::ScanComplete(
                    networking::handler::ScanComplete::from_le_stream_tolerant(stream)?,
                ),
            )),
            networking::handler::StackStatus::ID => {
                Ok(Self::Networking(networking::handler::Handler::StackStatus(
                    networking::handler::StackStatus::from_le_stream_tolerant(stream)?,
                )))
            }
            networking::handler::UnusedPanIdFound::ID => Ok(Self::Networking(
                networking::handler::Handler::UnusedPanIdFound(
                    networking::handler::UnusedPanIdFound::from_le_stream_tolerant(stream)?,
                ),
            )),
            // Security callbacks.
            security::handler::SwitchNetworkKey::ID => Ok(Self::Security(
                security::handler::Handler::SwitchNetworkKey(
                    security::handler::SwitchNetworkKey::from_le_stream_tolerant(stream)?,
                ),
            )),
            security::handler::ZigbeeKeyEstablishment::ID => Ok(Self::Security(
                security::handler::Handler::ZigbeeKeyEstablishment(
                    security::handler::ZigbeeKeyEstablishment::from_le_stream_tolerant(stream)?
                        .into(),
                ),
            )),
            // Trust Center callbacks.
            trust_center::handler::TrustCenterJoin::ID => Ok(Self::TrustCenter(
                trust_center::handler::Handler::TrustCenterJoin(
                    trust_center::handler::TrustCenterJoin::from_le_stream_tolerant(stream)?,
                ),
            )),
            // Utilities callbacks.
            utilities::handler::CounterRollover::ID => Ok(Self::Utilities(
                utilities::handler::Handler::CounterRollover(
                    utilities::handler::CounterRollover::from_le_stream_tolerant(stream)?,
                ),
            )),
            utilities::handler::CustomFrame::ID => {
                Ok(Self::Utilities(utilities::handler::Handler::CustomFrame(
                    utilities::handler::CustomFrame::from_le_stream_tolerant(stream)?.into(),
                )))
            }
            utilities::handler::StackTokenChanged::ID => Ok(Self::Utilities(
                utilities::handler::Handler::StackTokenChanged(
                    utilities::handler::StackTokenChanged::from_le_stream_tolerant(stream)?,
                ),
            )),
            utilities::handler::Timer::ID => {
                Ok(Self::Utilities(utilities::handler::Handler::Timer(
                    utilities::handler::Timer::from_le_stream_tolerant(stream)?,
                )))
            }
            // ZLL callbacks.
            zll::handler::AddressAssignment::ID => {
                Ok(Self::Zll(zll::handler::Handler::AddressAssignment(
                    zll::handler::AddressAssignment::from_le_stream_tolerant(stream)?,
                )))
            }
            zll::handler::NetworkFound::ID => Ok(Self::Zll(zll::handler::Handler::NetworkFound(
                zll::handler::NetworkFound::from_le_stream_tolerant(stream)?,
            ))),
            zll::handler::ScanComplete::ID => Ok(Self::Zll(zll::handler::Handler::ScanComplete(
                zll::handler::ScanComplete::from_le_stream_tolerant(stream)?,
            ))),
            zll::handler::TouchLinkTarget::ID => {
                Ok(Self::Zll(zll::handler::Handler::TouchLinkTarget(
                    zll::handler::TouchLinkTarget::from_le_stream_tolerant(stream)?,
                )))
            }
            _ => Err(Decode::InvalidFrameId(id)),
        }
    }
}
