//! Parameters for the [`Networking::get_duty_cycle_state`](crate::Networking::get_duty_cycle_state) command.

use num_traits::FromPrimitive;

use crate::Error;
use crate::ember::Status;
use crate::ember::duty_cycle::State;
use crate::error::ValueError;

crate::frame::parameters::frame!(
    0x0035,
    {},
    { status: u8, returned_state: u8 } => Networking(networking)::GetDutyCycleState,
    impl {
        /// Converts the response into [`State`] or an appropriate [`Error`] depending on its status.
        impl TryFrom<Response> for State {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                Status::check(response.status)?;
                Self::from_u8(response.returned_state)
                        .ok_or_else(|| ValueError::EmberDutyCycleState(response.returned_state).into())
            }
        }
    }
);
