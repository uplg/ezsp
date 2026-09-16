//! Parameters for the [`Networking::form_network`](crate::Networking::form_network) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::network::Parameters;

crate::frame::parameters::frame!(
    0x001E,
    { parameters: Parameters },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(parameters: Parameters) -> Self {
                Self { parameters }
            }
        }
    },
    { status: u8 } => Networking(networking)::FormNetwork,
    impl {
        /// Converts the response into `()` or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
