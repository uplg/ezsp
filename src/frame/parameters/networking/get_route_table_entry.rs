//! Parameters for the [`Networking::get_route_table_entry`](crate::Networking::get_route_table_entry) command.

use crate::Error;
use crate::ember::Status;
use crate::ember::route::TableEntry;

crate::frame::parameters::frame!(
    0x007B,
    { index: u8 },
    impl {
        impl Command {
            /// Creates command parameters.
            #[must_use]
            pub const fn new(index: u8) -> Self {
                Self { index }
            }
        }
    },
    { status: u8, value: TableEntry } => Networking(networking)::GetRouteTableEntry,
    impl {
        /// Convert a response into a [`TableEntry`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for TableEntry {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Ok(response.value)
            }
        }
    }
);
