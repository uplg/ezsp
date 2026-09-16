//! Parameters for the [`Networking::leave_network`](crate::Networking::leave_network) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x0020,
    {},
    { status: u8 } => Networking(networking)::LeaveNetwork,
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
