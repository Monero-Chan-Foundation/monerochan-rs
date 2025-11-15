mod memory;
mod program;
mod word;

pub use memory::*;
pub use program::*;
pub use word::*;

use monerochan_stark::air::{BaseAirBuilder, MONEROCHANAirBuilder};

/// A trait which contains methods related to memory interactions in an AIR.
pub trait MONEROCHANCoreAirBuilder:
    MONEROCHANAirBuilder + WordAirBuilder + MemoryAirBuilder + ProgramAirBuilder
{
}

impl<AB: BaseAirBuilder> MemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder> ProgramAirBuilder for AB {}
impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder + MONEROCHANAirBuilder> MONEROCHANCoreAirBuilder for AB {}
