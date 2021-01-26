// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Divisor used to compute the allowed dust outputs on an address.
/// The amount of dust outputs on an address is calculated by:
pub const DUST_ALLOWANCE_DIVISOR: u64 = 100_000;

/// Maximum number of dust outputs for an address.
pub const DUST_OUTPUTS_MAX: u64 = 100;

/// Minimum deposit amount.
pub const DUST_ALLOWANCE_MINIMUM: u64 = 1_000_000;

/// `dust_allowance_sum` is the sum of all the amounts of all unspent SigLockedDustAllowanceOutputs on an address.
/// The maximum number of allowed dust outputs on this address is `dust_allowance_sum` divided by
/// `DUST_ALLOWANCE_DIVISOR` and rounded down, i.e. 10 outputs for each 1 Mi deposited.
/// Regardless of `dust_allowance_sum`, the number of dust outputs must never exceed `DUST_OUTPUTS_MAX` per address.
#[allow(dead_code)]
pub(crate) fn dust_outputs_max(dust_allowance_sum: u64) -> usize {
    std::cmp::min(dust_allowance_sum / DUST_ALLOWANCE_DIVISOR, DUST_OUTPUTS_MAX) as usize
}
