//! Public synthetic append statement. Hash permutations are authenticated by the AIR,
//! never recomputed here. Lengths, framing, padding, links and node order are checked here.
use core::poseidon::poseidon_hash_span;
use stwo_verifier_core::channel::{Channel,ChannelTrait};
use stwo_verifier_core::fields::qm31::{QM31Trait};
use stwo_verifier_core::fields::m31::M31;

pub const DOMAIN: felt252='M31_APPEND_V1';
pub const P: u32=2147483647;
pub const RELATION_ID: u32=0x4d333150;
#[derive(Copy,Drop,Serde)]
pub struct Request { pub input: Span<u32>, pub output: Span<u32> }
#[derive(Copy,Drop,Serde)]
pub struct Step { pub siblings: Span<Span<u32>>, pub requests: Span<Request> }
#[derive(Copy,Drop,Serde)]
pub struct Statement {
    pub chain_id: felt252,
    pub pool: felt252,
    pub old_count: u64,
    pub new_count: u64,
    pub old_root: Span<u32>,
    pub new_root: Span<u32>,
    pub commitments: Span<felt252>,
    pub steps: Span<Step>,
}
#[derive(Drop)]
pub struct PublicData { pub requests: Array<Request>, pub log_size: u32, pub rows: u32 }

pub fn canonical(words: Span<u32>, length: usize) {
    assert(words.len()==length,'WORD_LENGTH');
    for word in words { assert(*word<P,'NONCANONICAL_M31'); };
}
pub fn packed(words: Span<u32>) -> (felt252,felt252) {
    canonical(words,9);
    let mut low: felt252=0;
    let mut factor: felt252=1;
    for i in 0_usize..8 { low+=factor*(*words.at(i)).into(); factor*=0x80000000; };
    (low,(*words.at(8)).into())
}
fn extend(ref output: Array<u32>, values: Span<u32>) {
    for value in values { output.append(*value); };
}
fn felt_words(value: felt252) -> Array<u32> {
    let mut wide: u256=value.into();
    let mut words=array![];
    for _ in 0_u32..9 { words.append((wide%0x10000000).try_into().unwrap()); wide/=0x10000000; };
    assert(wide==0,'FELT_TOP_BITS');
    words
}
fn count_words(value: u64) -> Array<u32> {
    array![(value%0x10000000).try_into().unwrap(),(value/0x10000000).try_into().unwrap()]
}
fn framed(kind: u32,level: u32,left: Span<u32>,right: Span<u32>) -> Array<u32> {
    let mut words=array![0x544d5031,1,kind,level];
    extend(ref words,left); extend(ref words,right); words
}
fn empty_leaf() -> Span<u32> {
    // Pinned Plonky3 oracle: Pad10Sponge([0x544d5031,1,3,0]).
    array![588219270,1912894104,1451304488,1990490117,350701116,1513791928,68338834,1281125379,519559439].span()
}
fn check_hash(message: Span<u32>,mut requests: Span<Request>) -> Span<u32> {
    let count=if message.len()==13 { 1 } else { assert(message.len()==22,'MESSAGE_SHAPE'); 2 };
    assert(requests.len()==count,'HASH_REQUEST_COUNT');
    let mut state=array![];
    for _ in 0_u32..24 { state.append(0_u32); };
    let mut offset: usize=0;
    loop {
        let request=*requests.pop_front().unwrap();
        let remaining=message.len()-offset;
        let take=if remaining<15 { remaining } else { 15 };
        let mut expected=array![];
        for i in 0_usize..15 {
            expected.append(if i<take { *message.at(offset+i) } else if i==take { 1 } else { 0 });
        };
        for i in 15_usize..24 { expected.append(*state.at(i)); };
        assert(expected.span()==request.input,'SPONGE_INPUT');
        // Both supported message lengths end in a partial block; the capacity is retained.
        state=array![];
        extend(ref state,request.output);
        offset+=take;
        if remaining<=15 { break; }
    };
    assert(requests.is_empty(),'UNCONSUMED_HASH_REQUEST');
    state.span().slice(0,9)
}
fn parent(level: u32,index: u64,current: Span<u32>,sibling: Span<u32>,requests: Span<Request>) -> Span<u32> {
    let message=if index%2==0 { framed(2,level,current,sibling) } else { framed(2,level,sibling,current) };
    check_hash(message.span(),requests)
}
pub fn validate(statement: Statement) -> PublicData {
    let n=statement.commitments.len();
    assert(n==1 || n==2,'BATCH_SIZE');
    assert(statement.steps.len()==n,'STEP_COUNT');
    let pool: u256=statement.pool.into();
    assert(pool>0 && pool<0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00,'POOL_ADDRESS');
    assert(statement.old_count<=0x100000000,'OLD_COUNT');
    assert(statement.new_count==statement.old_count+n.into(),'NEW_COUNT');
    assert(statement.new_count<=0x100000000,'TREE_CAPACITY');
    canonical(statement.old_root,9); canonical(statement.new_root,9);
    let mut all_requests=array![];
    let mut current_root=statement.old_root;
    let mut step_index: usize=0;
    for step in statement.steps {
        assert(step.siblings.len()==32,'PATH_LENGTH');
        assert(step.requests.len()==129,'REQUEST_COUNT');
        for sibling in step.siblings { canonical(*sibling,9); };
        for request in step.requests {
            canonical(*request.input,24); canonical(*request.output,24);
            all_requests.append(*request);
        };
        let commitment=*statement.commitments.at(step_index);
        let mut new_value=check_hash(framed(1,0,felt_words(commitment).span(),[].span()).span(),step.requests.slice(0,1));
        let mut old_value=empty_leaf();
        let mut index=statement.old_count+step_index.into();
        let mut level: usize=0;
        while level<32 {
            let sibling=*step.siblings.at(level);
            old_value=parent(level+1,index,old_value,sibling,step.requests.slice(1+4*level,2));
            new_value=parent(level+1,index,new_value,sibling,step.requests.slice(3+4*level,2));
            index/=2; level+=1;
        };
        assert(old_value==current_root,'OLD_PATH_ROOT');
        current_root=new_value;
        step_index+=1;
    };
    assert(current_root==statement.new_root,'NEW_PATH_ROOT');
    PublicData { requests:all_requests, log_size:if n==1 { 8 } else { 9 }, rows:if n==1 { 256 } else { 512 } }
}
pub fn mix_statement(statement: Statement,ref channel: Channel) {
    let mut words=array![0x544d5041,1,statement.commitments.len()];
    extend(ref words,felt_words(statement.chain_id).span());
    extend(ref words,felt_words(statement.pool).span());
    extend(ref words,count_words(statement.old_count).span());
    extend(ref words,count_words(statement.new_count).span());
    extend(ref words,statement.old_root); extend(ref words,statement.new_root);
    for commitment in statement.commitments { extend(ref words,felt_words(*commitment).span()); };
    for step in statement.steps {
        for sibling in step.siblings { extend(ref words,*sibling); };
        for request in step.requests { extend(ref words,*request.input); extend(ref words,*request.output); };
    };
    channel.mix_u64(words.len().into());
    let mut felts=array![];
    let mut remaining=words.span();
    while !remaining.is_empty() {
        let mut limbs: Array<M31>=array![];
        for _ in 0_u32..4 { limbs.append((*remaining.pop_front().unwrap_or(@0)).try_into().unwrap()); };
        felts.append(QM31Trait::from_fixed_array((*limbs.span().try_into().unwrap()).unbox()));
    };
    channel.mix_felts(felts.span());
}
pub fn public_values(statement: Statement) -> Span<felt252> {
    let (old_low,old_high)=packed(statement.old_root);
    let (new_low,new_high)=packed(statement.new_root);
    let n: felt252=statement.commitments.len().into();
    let mut preimage=array![DOMAIN,statement.chain_id,statement.pool,old_low,old_high,statement.old_count.into(),n];
    for commitment in statement.commitments { preimage.append(*commitment); };
    preimage.append(new_low); preimage.append(new_high); preimage.append(statement.new_count.into());
    array![DOMAIN,statement.chain_id,statement.pool,old_low,old_high,statement.old_count.into(),poseidon_hash_span(preimage.span()),n].span()
}
