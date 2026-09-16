//! Parameters for the [`Networking::send_link_power_delta_request`](crate::Networking::send_link_power_delta_request) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x00F7,
    {},
    { status: u8 } => Networking(networking)::SendLinkPowerDeltaRequest,
    impl {
        /// Convert a response into `()` or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
