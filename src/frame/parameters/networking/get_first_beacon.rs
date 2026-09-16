//! Parameters for the [`Networking::get_first_beacon`](crate::Networking::get_first_beacon) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::beacon::Iterator;

crate::frame::parameters::frame!(
    0x003D,
    {},
    { status: u8, beacon_iterator: Iterator } => Networking(networking)::GetFirstBeacon,
    impl {
        /// Converts the response into [`Iterator`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for Iterator {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.beacon_iterator)
            }
        }
    }
);
