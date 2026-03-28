//! Parameters for the  [`Security::import_transient_key`](crate::Security::import_transient_key) command.

use le_stream::{FromLeStream, ToLeStream};
use num_traits::FromPrimitive;
use silizium::zigbee::security::man::{Flags, Key};
use silizium::Status;

use crate::ember::Eui64;
use crate::frame::Parameter;
use crate::Error;

const ID: u16 = 0x0111;

/// Legacy (EZSP ≤ v13) wire format: `EUI64(8B) + Key(16B) + Flags(1B)`.
///
/// The upstream SiLabs SDK added a `SecManContext` prefix in EZSP v14, but most
/// NCP firmware in the field (including the ELELABS/SkyConnect images commonly
/// used with Zigbee2MQTT) still expects the legacy format.
#[derive(Clone, Debug, Eq, PartialEq, ToLeStream)]
pub(crate) struct Command {
    eui64: Eui64,
    plaintext_key: Key,
    flags: u8,
}

impl Command {
    #[must_use]
    pub const fn new(eui64: Eui64, plaintext_key: Key, flags: Flags) -> Self {
        Self {
            eui64,
            plaintext_key,
            flags: flags.bits(),
        }
    }
}

impl Parameter for Command {
    const ID: u16 = ID;
}

/// Response parameters.
#[derive(Clone, Debug, Eq, PartialEq, FromLeStream)]
pub struct Response {
    status: u32,
}

impl Parameter for Response {
    const ID: u16 = ID;
}

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
