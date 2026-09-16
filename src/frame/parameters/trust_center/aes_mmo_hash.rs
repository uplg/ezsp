//! Parameters for the [`TrustCenter::aes_mmo_hash`](crate::TrustCenter::aes_mmo_hash) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::aes::MmoHashContext;
use crate::types::ByteSizedVec;

crate::frame::parameters::frame!(
    0x006F,
    { context: MmoHashContext, finalize: bool, data: ByteSizedVec<u8> },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(context: MmoHashContext, finalize: bool, data: ByteSizedVec<u8>) -> Self {
                Self {
                    context,
                    finalize,
                    data,
                }
            }
        }
    },
    { status: u8, return_context: MmoHashContext } => TrustCenter(trust_center)::AesMmoHash,
    impl {
        /// Convert the response into [`MmoHashContext`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for MmoHashContext {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.return_context)
            }
        }
    }
);
