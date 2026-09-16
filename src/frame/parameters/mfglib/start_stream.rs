//! Parameters for the [`Mfglib::start_stream`](crate::Mfglib::start_stream) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x0087,
    {},
    { status: u8 } => MfgLib(mfglib)::StartStream,
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
