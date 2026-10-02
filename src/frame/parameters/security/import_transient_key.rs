//! Parameters for the  [`Security::import_transient_key`](crate::Security::import_transient_key) command.

use num_traits::FromPrimitive;
use silizium::Status;
use silizium::zigbee::security::man::{Context, Flags, Key};

use crate::Error;
use crate::ember::Eui64;

/// First EZSP protocol version whose `importTransientKey` command carries a
/// leading `SecManContext`.
///
/// NCPs speaking EZSP v13 and older (e.g. `EmberZNet` 7.4.x on Sonoff MG21
/// dongles) expect the legacy layout `EUI64(8B) + Key(16B) + Flags(1B)`. Sent
/// the v14+ layout, they silently misparse the key and the security handshake
/// of joining devices fails.
pub const MIN_CONTEXT_VERSION: u8 = 14;

crate::frame::parameters::frame!(
    0x0111,
    // `None` encodes no bytes, which yields the legacy (EZSP <= v13) layout.
    { context: Option<Context>, eui64: Eui64, plaintext_key: Key, flags: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            ///
            /// The `context` is sent only to NCPs that negotiated EZSP
            /// v[`MIN_CONTEXT_VERSION`] or newer; it is dropped for older NCPs,
            /// which expect the legacy layout without it.
            #[must_use]
            pub const fn new(context: Context, eui64: Eui64, plaintext_key: Key, flags: Flags) -> Self {
                Self {
                    context: Some(context),
                    eui64,
                    plaintext_key,
                    flags: flags.bits(),
                }
            }

            /// Adapts the wire layout to the negotiated EZSP protocol version.
            #[must_use]
            pub(crate) const fn for_version(mut self, protocol_version: u8) -> Self {
                if protocol_version < MIN_CONTEXT_VERSION {
                    self.context = None;
                }

                self
            }
        }
    },
    { status: u32 } => Security(security)::ImportTransientKey,
    impl {
        /// Convert the response into `()` or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                match Status::from_u32(response.status).ok_or(response.status) {
                    Ok(Status::Ok) => Ok(()),
                    other => Err(other.into()),
                }
            }
        }
    }
);

#[cfg(test)]
mod tests {
    use le_stream::ToLeStream;
    use silizium::zigbee::security::man::{Context, DerivedKeyType, KeyType};

    use super::*;

    const EUI64: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    fn command() -> Command {
        let context = Context::new(
            KeyType::TcLink,
            0,
            DerivedKeyType::None,
            EUI64.into(),
            0,
            Flags::empty(),
            0,
        );
        Command::new(context, EUI64.into(), [0xAB; 16], Flags::empty())
    }

    #[test]
    fn legacy_layout_for_ezsp_v13() {
        let bytes: Vec<u8> = command().for_version(13).to_le_stream().collect();
        let mut expected: Vec<u8> = Vec::new();
        expected.extend(Eui64::from(EUI64).to_le_stream());
        expected.extend([0xAB; 16]);
        expected.push(0x00);
        assert_eq!(bytes.len(), 8 + 16 + 1);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn context_layout_for_ezsp_v14() {
        let bytes: Vec<u8> = command()
            .for_version(MIN_CONTEXT_VERSION)
            .to_le_stream()
            .collect();
        assert_eq!(bytes.len(), 17 + 8 + 16 + 1);
        assert_eq!(
            &bytes[17..25],
            Eui64::from(EUI64).to_le_stream().collect::<Vec<_>>()
        );
    }
}
