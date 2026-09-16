//! Parameters for the [`Cbke::get_certificate283k1`](crate::Cbke::get_certificate283k1) command.

use crate::Error;
use crate::ember::{Certificate283k1Data, Status};

crate::frame::parameters::frame!(
    0x00EC,
    {},
    { status: u8, local_cert: Certificate283k1Data } => Cbke(cbke)::GetCertificate283k1,
    impl {
        /// Converts the response into [`Certificate283k1Data`]
        /// or an appropriate [`Error`] by evaluating its status field.
        impl TryFrom<Response> for Certificate283k1Data {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.local_cert)
            }
        }
    }
);
