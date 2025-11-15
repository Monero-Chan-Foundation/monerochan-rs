#![no_main]
monerochan_runtime::entrypoint!(main);

use lib::{Account, Transaction}; // Custom structs.
use serde_json::Value; // Generic JSON.

pub fn main() {
    // read generic JSON example inputs.
    let data_str = monerochan_runtime::io::read::<String>();
    let key = monerochan_runtime::io::read::<String>();

    // read custom struct example inputs.
    let mut old_account_state = monerochan_runtime::io::read::<Account>();
    let txs = monerochan_runtime::io::read::<Vec<Transaction>>();

    // do stuff with generic JSON.
    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];

    // do stuff with custom struct.
    let new_account_state = &mut old_account_state;
    for tx in txs {
        if tx.from == new_account_state.account_name {
            new_account_state.balance -= tx.amount;
        }
        if tx.to == new_account_state.account_name {
            new_account_state.balance += tx.amount;
        }
    }
    monerochan_runtime::io::commit(&val);
    monerochan_runtime::io::commit(&new_account_state);
}
