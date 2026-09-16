//! Parameters for the [`Utilities::get_xncp_info`](crate::Utilities::get_xncp_info) command.

use le_stream::{FromLeStream, ToLeStream};

use crate::ember::Status;
use crate::{Error, ValueError};

crate::frame::parameters::frame!(
    0x0013,
    {},
    { status: u8, payload: Option<Payload> } => Utilities(utilities)::GetXncpInfo,
    impl {
        /// Convert the response into a [`Payload`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for Payload {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                response
                        .payload
                        .ok_or_else(|| ValueError::MissingPayload.into())
            }
        }
    }
);

/// Payload of the get XNCP info command.
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromLeStream, ToLeStream)]
pub struct Payload {
    manufacturer_id: u16,
    version_number: u16,
}

impl Payload {
    /// Returns the manufacturer ID.
    #[must_use]
    pub const fn manufacturer_id(self) -> u16 {
        self.manufacturer_id
    }

    /// Returns the version number.
    #[must_use]
    pub const fn version_number(self) -> u16 {
        self.version_number
    }
}
