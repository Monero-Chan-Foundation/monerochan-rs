#[cfg(test)]
mod tests {
    use sha2::Digest;
    use monerochan::MONEROCHANPublicValues;
    use monerochan_test::monerochan_test;

    #[monerochan_test("sha2_v0_9_9", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_9_9_expected_digest_lte_100_times(
        stdin: &mut monerochan::MONEROCHANStdin,
    ) -> impl FnOnce(MONEROCHANPublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[monerochan_test("sha2_v0_10_6", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_10_6_expected_digest_lte_100_times(
        stdin: &mut monerochan::MONEROCHANStdin,
    ) -> impl FnOnce(MONEROCHANPublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[monerochan_test("sha2_v0_10_8", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_10_8_expected_digest_lte_100_times(
        stdin: &mut monerochan::MONEROCHANStdin,
    ) -> impl FnOnce(MONEROCHANPublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    fn sha2_expected_digest_lte_100_times(
        stdin: &mut monerochan::MONEROCHANStdin,
    ) -> impl FnOnce(MONEROCHANPublicValues) {
        use monerochan_test::DEFAULT_CORPUS_COUNT;
        use monerochan_test::DEFAULT_CORPUS_MAX_LEN;

        let mut preimages = monerochan_test::random_preimages_with_bounded_len(
            DEFAULT_CORPUS_COUNT,
            DEFAULT_CORPUS_MAX_LEN,
        );

        monerochan_test::add_hash_fn_edge_cases(&mut preimages);

        let digests = preimages
            .iter()
            .map(|preimage| {
                let mut sha256 = sha2::Sha256::new();
                sha256.update(preimage);

                sha256.finalize().into()
            })
            .collect::<Vec<[u8; 32]>>();

        // Write the number of preimages to the MONEROCHANStdin
        // This should be equal to the number of digests.
        stdin.write(&preimages.len());
        preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));

        move |mut public| {
            for digest in digests {
                let committed = public.read::<[u8; 32]>();

                assert_eq!(digest, committed);
            }
        }
    }

    #[monerochan_test("sha3", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha3_expected_digest_lte_100_times(
        stdin: &mut monerochan::MONEROCHANStdin,
    ) -> impl FnOnce(MONEROCHANPublicValues) {
        use sha3::Digest;
        use sha3::Sha3_256;

        use monerochan_test::DEFAULT_CORPUS_COUNT;
        use monerochan_test::DEFAULT_CORPUS_MAX_LEN;

        let mut preimages: Vec<Vec<u8>> = monerochan_test::random_preimages_with_bounded_len(
            DEFAULT_CORPUS_COUNT,
            DEFAULT_CORPUS_MAX_LEN,
        );

        monerochan_test::add_hash_fn_edge_cases(&mut preimages);

        let digests = preimages
            .iter()
            .map(|preimage| {
                let mut sha3 = Sha3_256::new();
                sha3.update(preimage);

                sha3.finalize().into()
            })
            .collect::<Vec<[u8; 32]>>();

        // Write the number of preimages to the MONEROCHANStdin
        // This should be equal to the number of digests.
        stdin.write(&preimages.len());
        preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));

        move |mut public| {
            for digest in digests {
                let committed = public.read::<[u8; 32]>();
                assert_eq!(digest, committed);
            }
        }
    }
}
