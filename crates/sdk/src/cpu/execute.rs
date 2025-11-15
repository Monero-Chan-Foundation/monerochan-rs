//! # CPU Execution
//!
//! This module provides a builder for simulating the execution of a program on the CPU.

use anyhow::Result;
use monerochan_core_executor::{ExecutionReport, HookEnv, IoWriter, MONEROCHANContextBuilder};
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_primitives::io::MONEROCHANPublicValues;
use monerochan_prover::{components::CpuProverComponents, MONEROCHANProver};

/// A builder for simulating the execution of a program on the CPU.
///
/// This builder providers a typed interface for configuring the MONEROCHAN RISC-V executor. The builder
/// is used for all the different variants of the [`crate::ProverClient`].
pub struct CpuExecuteBuilder<'a> {
    pub(crate) elf: &'a [u8],
    pub(crate) stdin: MONEROCHANStdin,
    pub(crate) prover: &'a MONEROCHANProver<CpuProverComponents>,
    pub(crate) context_builder: MONEROCHANContextBuilder<'a>,
}

impl<'a> CpuExecuteBuilder<'a> {
    /// Add a executor [`monerochan_core_executor::Hook`] into the context.
    ///
    /// # Arguments
    /// * `fd` - The file descriptor that triggers this execution hook.
    /// * `f` - The function to invoke when the hook is triggered.
    ///
    /// # Details
    /// Hooks may be invoked from within MONEROCHAN by writing to the specified file descriptor `fd`
    /// with [`monerochan_runtime::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`monerochan_runtime::io::read`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client
    ///     .execute(elf, &stdin)
    ///     .with_hook(1, |env, data| {
    ///         println!("Hook triggered with data: {:?}", data);
    ///         vec![vec![1, 2, 3]]
    ///     })
    ///     .run();
    /// ```
    #[must_use]
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// # Arguments
    /// * `max_cycles` - The maximum number of cycles to use for execution.
    ///
    /// # Details
    /// If the cycle limit is exceeded, execution will fail with the
    /// [`monerochan_core_executor::ExecutionError::ExceededCycleLimit`]. This is useful for preventing
    /// infinite loops in the and limiting the execution time of the program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin).cycle_limit(1000000).run();
    /// ```
    #[must_use]
    pub fn cycle_limit(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Whether to enable deferred proof verification in the executor.
    ///
    /// # Arguments
    /// * `value` - Whether to enable deferred proof verification in the executor.
    ///
    /// # Details
    /// Default: `true`. If set to `false`, the executor will skip deferred proof verification.
    /// This is useful for reducing the execution time of the program and optimistically assuming
    /// that the deferred proofs are correct. Can also be used for mock proof setups that require
    /// verifying mock compressed proofs.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin).deferred_proof_verification(false).run();
    /// ```
    #[must_use]
    pub fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_deferred_proof_verification(value);
        self
    }

    /// Whether to enable gas calculation in the executor.
    ///
    /// # Arguments
    /// * `value` - Whether to enable gas calculation in the executor.
    ///
    /// # Details
    /// Default: `true`. If set to `false`, the executor will not calculate gas.
    /// This is useful for reducing the execution time of the program, since gas calculation
    /// must perform extra work to simulate parts of the proving process.
    ///
    /// Gas may be retrieved through the [`ExecutionReport`] available through [`Self::run`].
    /// It will be `None` if and only if this option is disabled.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin).calculate_gas(false).run();
    /// ```
    #[must_use]
    pub fn calculate_gas(mut self, value: bool) -> Self {
        self.context_builder.calculate_gas(value);
        self
    }

    /// Override the default stdout of the guest program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let mut stdout = Vec::new();
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// client.execute(elf, &stdin).stdout(&mut stdout).run();
    /// ```
    #[must_use]
    pub fn stdout<W: IoWriter>(mut self, writer: &'a mut W) -> Self {
        self.context_builder.stdout(writer);
        self
    }

    /// Override the default stdout of the guest program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let mut stderr = Vec::new();
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// client.execute(elf, &stdin).stderr(&mut stderr).run();
    /// ```
    #[must_use]
    pub fn stderr<W: IoWriter>(mut self, writer: &'a mut W) -> Self {
        self.context_builder.stderr(writer);
        self
    }

    /// Executes the program on the input with the built arguments.
    ///
    /// # Details
    /// This method will execute the program on the input with the built arguments. If the program
    /// fails to execute, the method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    pub fn run(self) -> Result<(MONEROCHANPublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, mut context_builder } = self;
        let context = context_builder.build();
        let (pv, _, report) = prover.execute(elf, &stdin, context)?;
        Ok((pv, report))
    }
}
