//! Parameters for the [`TokenInterface::gp_security_test_vectors`](crate::TokenInterface::gp_security_test_vectors) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x0117,
    {},
    { status: u8 } => TokenInterface(token_interface)::GpSecurityTestVectors,
    impl {
        /// Convert the response into `()` or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
