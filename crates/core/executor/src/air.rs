use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};
use monerochan_stark::shape::Shape;
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};
use subenum::subenum;

/// RV32IM AIR Identifiers.
///
/// These identifiers are for the various chips in the rv32im prover. We need them in the
/// executor to compute the memory cost of the current shard of execution.
///
/// The subenums categorize the AIRs:
/// - [`CoreAirId`]: AIRs that are not part of precompile shards and not the program or byte AIR.
/// - [`MemoryAirId`]: AIRs related to memory operations (init, finalize, global).
/// - [`PrecompileAirId`]: AIRs for cryptographic precompiles (SHA, Ed25519, secp256k1, etc.).
#[subenum(CoreAirId, MemoryAirId, PrecompileAirId)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    IntoStaticStr,
    PartialOrd,
    Ord,
    Enum,
)]
pub enum RiscvAirId {
    /// The CPU chip.
    #[subenum(CoreAirId)]
    Cpu = 0,
    /// The program chip.
    Program = 1,
    /// The SHA-256 extend chip.
    #[subenum(PrecompileAirId)]
    ShaExtend = 2,
    /// The SHA-256 compress chip.
    #[subenum(PrecompileAirId)]
    ShaCompress = 3,
    /// The Edwards add assign chip.
    #[subenum(PrecompileAirId)]
    EdAddAssign = 4,
    /// The Edwards decompress chip.
    #[subenum(PrecompileAirId)]
    EdDecompress = 5,
    /// The secp256k1 decompress chip.
    #[subenum(PrecompileAirId)]
    Secp256k1Decompress = 6,
    /// The secp256k1 add assign chip.
    #[subenum(PrecompileAirId)]
    Secp256k1AddAssign = 7,
    /// The secp256k1 double assign chip.
    #[subenum(PrecompileAirId)]
    Secp256k1DoubleAssign = 8,
    /// The secp256r1 decompress chip.
    #[subenum(PrecompileAirId)]
    Secp256r1Decompress = 9,
    /// The secp256r1 add assign chip.
    #[subenum(PrecompileAirId)]
    Secp256r1AddAssign = 10,
    /// The secp256r1 double assign chip.
    #[subenum(PrecompileAirId)]
    Secp256r1DoubleAssign = 11,
    /// The Keccak permute chip.
    #[subenum(PrecompileAirId)]
    KeccakPermute = 12,
    /// The bn254 add assign chip.
    #[subenum(PrecompileAirId)]
    Bn254AddAssign = 13,
    /// The bn254 double assign chip.
    #[subenum(PrecompileAirId)]
    Bn254DoubleAssign = 14,
    /// The bls12-381 add assign chip.
    #[subenum(PrecompileAirId)]
    Bls12381AddAssign = 15,
    /// The bls12-381 double assign chip.
    #[subenum(PrecompileAirId)]
    Bls12381DoubleAssign = 16,
    /// The uint256 mul mod chip.
    #[subenum(PrecompileAirId)]
    Uint256MulMod = 17,
    /// The u256 xu2048 mul chip.
    #[subenum(PrecompileAirId)]
    U256XU2048Mul = 18,
    /// The bls12-381 fp op assign chip.
    #[subenum(PrecompileAirId)]
    Bls12381FpOpAssign = 19,
    /// The bls12-831 fp2 add sub assign chip.
    #[subenum(PrecompileAirId)]
    Bls12381Fp2AddSubAssign = 20,
    /// The bls12-831 fp2 mul assign chip.
    #[subenum(PrecompileAirId)]
    Bls12381Fp2MulAssign = 21,
    /// The bn254 fp2 add sub assign chip.
    #[subenum(PrecompileAirId)]
    Bn254FpOpAssign = 22,
    /// The bn254 fp op assign chip.
    #[subenum(PrecompileAirId)]
    Bn254Fp2AddSubAssign = 23,
    /// The bn254 fp2 mul assign chip.
    #[subenum(PrecompileAirId)]
    Bn254Fp2MulAssign = 24,
    /// The bls12-381 decompress chip.
    #[subenum(PrecompileAirId)]
    Bls12381Decompress = 25,
    /// The syscall core chip.
    #[subenum(CoreAirId)]
    SyscallCore = 26,
    /// The syscall precompile chip.
    SyscallPrecompile = 27,
    /// The div rem chip.
    #[subenum(CoreAirId)]
    DivRem = 28,
    /// The add sub chip.
    #[subenum(CoreAirId)]
    AddSub = 29,
    /// The bitwise chip.
    #[subenum(CoreAirId)]
    Bitwise = 30,
    /// The mul chip.
    #[subenum(CoreAirId)]
    Mul = 31,
    /// The shift right chip.
    #[subenum(CoreAirId)]
    ShiftRight = 32,
    /// The shift left chip.
    #[subenum(CoreAirId)]
    ShiftLeft = 33,
    /// The lt chip.
    #[subenum(CoreAirId)]
    Lt = 34,
    /// The memory instructions chip.
    #[subenum(CoreAirId)]
    MemoryInstrs = 35,
    /// The auipc chip.
    #[subenum(CoreAirId)]
    Auipc = 36,
    /// The branch chip.
    #[subenum(CoreAirId)]
    Branch = 37,
    /// The jump chip.
    #[subenum(CoreAirId)]
    Jump = 38,
    /// The syscall instructions chip.
    #[subenum(CoreAirId)]
    SyscallInstrs = 39,
    /// The memory global init chip.
    #[subenum(MemoryAirId)]
    MemoryGlobalInit = 40,
    /// The memory global finalize chip.
    #[subenum(MemoryAirId)]
    MemoryGlobalFinalize = 41,
    /// The memory local chip.
    #[subenum(CoreAirId)]
    MemoryLocal = 42,
    /// The global chip.
    #[subenum(CoreAirId, MemoryAirId)]
    Global = 43,
    /// The byte chip.
    Byte = 44,
}

impl RiscvAirId {
    /// Returns the AIRs that are not part of precompile shards and not the program or byte AIR.
    #[must_use]
    pub fn core() -> Vec<RiscvAirId> {
        vec![
            RiscvAirId::Cpu,
            RiscvAirId::AddSub,
            RiscvAirId::Mul,
            RiscvAirId::Bitwise,
            RiscvAirId::ShiftLeft,
            RiscvAirId::ShiftRight,
            RiscvAirId::DivRem,
            RiscvAirId::Lt,
            RiscvAirId::Auipc,
            RiscvAirId::MemoryLocal,
            RiscvAirId::MemoryInstrs,
            RiscvAirId::Branch,
            RiscvAirId::Jump,
            RiscvAirId::SyscallCore,
            RiscvAirId::SyscallInstrs,
            RiscvAirId::Global,
        ]
    }

    /// Whether the ID represents a core AIR.
    #[must_use]
    pub fn is_core(self) -> bool {
        CoreAirId::try_from(self).is_ok()
    }

    /// Whether the ID represents a memory AIR.
    #[must_use]
    pub fn is_memory(self) -> bool {
        MemoryAirId::try_from(self).is_ok()
    }

    /// Whether the ID represents a precompile AIR.
    #[must_use]
    pub fn is_precompile(self) -> bool {
        PrecompileAirId::try_from(self).is_ok()
    }

    /// The number of rows in the AIR produced by each event.
    #[must_use]
    pub fn rows_per_event(&self) -> usize {
        match self {
            Self::ShaCompress => 80,
            Self::ShaExtend => 48,
            Self::KeccakPermute => 24,
            _ => 1,
        }
    }

    /// Returns the string representation of the AIR.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl FromStr for RiscvAirId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let air = Self::iter().find(|chip| chip.as_str() == s);
        match air {
            Some(air) => Ok(air),
            None => Err(format!("Invalid RV32IMAir: {s}")),
        }
    }
}

impl Display for RiscvAirId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.as_str())
    }
}

/// Defines a set of maximal shapes for generating core proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaximalShapes {
    inner: Vec<EnumMap<CoreAirId, u32>>,
}

impl FromIterator<Shape<RiscvAirId>> for MaximalShapes {
    fn from_iter<T: IntoIterator<Item = Shape<RiscvAirId>>>(iter: T) -> Self {
        let mut maximal_shapes = Vec::new();
        for shape in iter {
            let mut maximal_shape = EnumMap::<CoreAirId, u32>::default();
            for (air, height) in shape {
                if let Ok(core_air) = CoreAirId::try_from(air) {
                    maximal_shape[core_air] = height as u32;
                } else if air != RiscvAirId::Program && air != RiscvAirId::Byte {
                    tracing::warn!("Invalid core air: {air}");
                }
            }
            maximal_shapes.push(maximal_shape);
        }
        Self { inner: maximal_shapes }
    }
}

impl MaximalShapes {
    /// Returns an iterator over the maximal shapes.
    pub fn iter(&self) -> impl Iterator<Item = &EnumMap<CoreAirId, u32>> {
        self.inner.iter()
    }
}
