//! Parameters for the [`Messaging::get_beacon_classification_params`](crate::Messaging::get_beacon_classification_params) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::beacon::ClassificationParams;

crate::frame::parameters::frame!(
    0x00F3,
    {},
    {
        status: u8,
        param: ClassificationParams,
    } => Messaging(messaging)::GetBeaconClassificationParams,
    impl {
        /// Converts the response into the [`ClassificationParams`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for ClassificationParams {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.param)
            }
        }
    }
);
