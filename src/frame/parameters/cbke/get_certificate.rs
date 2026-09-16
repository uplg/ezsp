//! Parameters for the [`Cbke::get_certificate`](crate::Cbke::get_certificate) command.

use crate::Error;
use crate::ember::{CertificateData, Status};

crate::frame::parameters::frame!(
    0x00A5,
    {},
    { status: u8, local_cert: CertificateData } => Cbke(cbke)::GetCertificate,
    impl {
        /// Converts the response into [`CertificateData`]
        /// or an appropriate [`Error`] by evaluating its status field.
        impl TryFrom<Response> for CertificateData {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.local_cert)
            }
        }
    }
);
