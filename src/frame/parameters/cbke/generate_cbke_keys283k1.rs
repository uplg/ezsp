//! Parameters for the [`Cbke::generate_cbke_keys`](crate::Cbke::generate_cbke_keys) command.

use crate::Error;
use crate::ember::Status;

crate::frame::parameters::frame!(
    0x00E8,
    {},
    { status: u8 } => Cbke(cbke)::GenerateCbkeKeys283k1,
    impl {
        /// Converts the response into `()` or an appropriate [`Error`] by evaluating its status field.
        impl TryFrom<Response> for () {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(())
            }
        }
    }
);
