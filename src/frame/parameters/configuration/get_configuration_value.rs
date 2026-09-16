//! Parameters for the [`Configuration::get_configuration_value`](crate::Configuration::get_configuration_value) command.

use crate::Error;
use crate::ezsp::Status;
use crate::ezsp::config::Id;

crate::frame::parameters::frame!(
    0x0052,
    { config_id: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub fn new(config_id: Id) -> Self {
                Self {
                    config_id: config_id.into(),
                }
            }
        }
    },
    { status: u8, value: u16 } => Configuration(configuration)::GetConfigurationValue,
    impl {
        /// Converts the response into a [`u16`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for u16 {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.value)
            }
        }
    }
);
