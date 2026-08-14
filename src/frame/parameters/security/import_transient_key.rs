//! Parameters for the  [`Security::import_transient_key`](crate::Security::import_transient_key) command.

use num_traits::FromPrimitive;
use silizium::Status;
use silizium::zigbee::security::man::{Flags, Key};

use crate::Error;
use crate::ember::Eui64;

// Legacy (EZSP ≤ v13) wire format: `EUI64(8B) + Key(16B) + Flags(1B)`.
//
// The upstream SiLabs SDK added a `SecManContext(17B)` prefix in EZSP v14,
// but v13 NCP firmware (e.g. Sonoff MG21 dongles) expects the legacy format;
// with the prefix the NCP silently misparses the key data and security
// handshakes for joining devices fail.
crate::frame::parameters::frame!(
    0x0111,
    { eui64: Eui64, plaintext_key: Key, flags: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(eui64: Eui64, plaintext_key: Key, flags: Flags) -> Self {
                Self {
                    eui64,
                    plaintext_key,
                    flags: flags.bits(),
                }
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
