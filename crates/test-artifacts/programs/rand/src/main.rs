#![no_main]
monerochan_runtime::entrypoint!(main);

use rand::Rng;

pub fn main() {
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        let num = rng.gen::<u64>();
        println!("{num}");
    }
}
