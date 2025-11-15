#![no_main]
monerochan_runtime::entrypoint!(main);

pub fn main() {
    assert_eq!(0, 1);
}
