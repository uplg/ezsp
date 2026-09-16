//! Parameters for the [`Mfglib::end`](crate::Mfglib::end) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x0084,
    {},
    { status: u8 } => MfgLib(mfglib)::End,
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
