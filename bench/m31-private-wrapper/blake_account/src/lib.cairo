//! PUBLIC HASH COST EXPERIMENT ONLY. Does not assert private membership validity.
#[derive(Drop, Serde)]
pub struct Job {
    pub byte_len: u32,
    pub words: Array<u32>,
    pub expected: [u32; 8],
}

#[starknet::contract(account)]
pub mod BlakeCostAccount {
    use starknet::{get_caller_address, get_contract_address, SyscallResultTrait};
    use starknet::syscalls::{
        get_class_hash_at_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall,
    };
    use core::poseidon::poseidon_hash_span;
    use super::Job;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn __validate__(self: @ContractState, data: Span<felt252>) -> felt252 {
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        assert!(info.tx_info.tip == 0, "PROVE_ONLY");
        for bound in info.tx_info.resource_bounds {
            assert!(*bound.max_price_per_unit == 0, "PROVE_ONLY");
        };
        'VALID'
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, mut data: Span<felt252>) {
        assert!(get_caller_address().into() == 0, "OS_ONLY");
        let jobs: Array<Job> = Serde::deserialize(ref data).expect('JOBS');
        assert!(data.is_empty(), "TRAILING_DATA");
        assert!(jobs.len() > 0 && jobs.len() <= 8192, "JOB_CAP");
        let count = jobs.len();
        let mut bytes: u32 = 0;
        let mut blocks: u32 = 0;
        let mut digest_words: Array<felt252> = array![];
        for job in jobs {
            bytes += job.byte_len;
            blocks += if job.byte_len == 0 { 1 } else { (job.byte_len + 63) / 64 };
            let actual = templar_blake_probe::digest_words(job.words.span(), job.byte_len);
            let [e0, e1, e2, e3, e4, e5, e6, e7] = job.expected;
            let expected = array![e0, e1, e2, e3, e4, e5, e6, e7];
            for i in 0_usize..8 {
                assert!(*actual.at(i) == *expected.at(i), "HASH_MISMATCH");
                digest_words.append((*actual.at(i)).into());
            };
        };
        let info = get_execution_info_v3_syscall().unwrap_syscall();
        let class_hash = get_class_hash_at_syscall(get_contract_address()).unwrap_syscall();
        let output = array![
            class_hash.into(), 'BLAKE_COST_V1', info.tx_info.chain_id,
            count.into(), bytes.into(), blocks.into(), poseidon_hash_span(digest_words.span()),
        ];
        send_message_to_l1_syscall(0, output.span()).unwrap_syscall();
    }
}
