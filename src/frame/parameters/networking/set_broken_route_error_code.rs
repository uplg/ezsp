//! Parameters for the [`Networking::set_broken_route_error_code`](crate::Networking::set_broken_route_error_code) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x0011,
    { error_code: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(error_code: u8) -> Self {
                Self { error_code }
            }
        }
    },
    { status: u8 } => Networking(networking)::SetBrokenRouteErrorCode,
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
