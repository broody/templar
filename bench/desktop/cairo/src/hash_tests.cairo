use desktop::hashing::{hash, pair, FR};
#[test]
fn vector_0() { assert_eq!(hash(array![].span()), 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e); }
#[test]
fn vector_1() { assert_eq!(hash(array![1].span()), 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373); }
#[test]
fn vector_2() { assert_eq!(hash(array![1,2].span()), 0x38682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383); }
#[test]
fn vector_3() { assert_eq!(hash(array![1,2,3].span()), 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8); }
#[test]
fn vector_4() { assert_eq!(hash(array![1,2,3,4].span()), 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9); }
#[test]
fn vector_7() { assert_eq!(hash(array![1,2,3,4,5,6,7].span()), 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238); }
#[test]
fn vector_27() { assert_eq!(hash(array![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27].span()), 0x270d69588d1ad52671e5e8026a58f1f13c17f3754a68dc358a6db504a7c20822); }
#[test]
fn large_inputs() { assert_eq!(hash(array![FR-1,FR-2].span()),0x2a3af28ae45056e36af2c3a829f1500c199a3f0aa681c199b7366d00676f0ca9); }
#[test]
#[should_panic(expected: ('NONCANONICAL',))]
fn rejects_noncanonical() { hash(array![FR].span()); }
#[test]
fn native_chain_32() { let mut acc: u256 = 1; for i in 0_u32..32_u32 { acc = pair(acc, 2 + i.into()); }; assert!(acc != 0); }
#[test]
fn starknet_chain_32() { let mut acc: felt252 = 1; for i in 0_u32..32_u32 { acc = core::poseidon::poseidon_hash_span(array![acc, 2 + i.into()].span()); }; assert!(acc != 0); }
