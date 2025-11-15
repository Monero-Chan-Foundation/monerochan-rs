#![no_main]
monerochan_runtime::entrypoint!(main);

use curve25519_dalek::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let times: usize = monerochan_runtime::io::read();

    for i in 0..times {
        println!("Decompressing the {i}th point");
        let compressed: CompressedEdwardsY = monerochan_runtime::io::read();
        let decompressed = compressed.decompress();

        monerochan_runtime::io::commit(&decompressed);
    }
}
