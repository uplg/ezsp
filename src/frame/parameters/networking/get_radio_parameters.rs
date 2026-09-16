//! Parameters for the [`Networking::get_radio_parameters`](crate::Networking::get_radio_parameters) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::multi_phy::radio::Parameters;

crate::frame::parameters::frame!(
    0x00FD,
    { phy_index: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(phy_index: u8) -> Self {
                Self { phy_index }
            }
        }
    },
    { status: u8, parameters: Parameters } => Networking(networking)::GetRadioParameters,
    impl {
        /// Converts the response into [`Parameters`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for Parameters {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.parameters)
            }
        }
    }
);
