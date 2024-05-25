use crate::channel_commit::CommitmentGadget;
use crate::merkle_tree::MerkleTreeProof;
use bitvm::bigint::bits::limb_to_be_bits_toaltstack;
use bitvm::treepp::*;

pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    pub fn push_merkle_tree_proof(merkle_proof: &MerkleTreeProof) -> Script {
        script! {
            { merkle_proof.leaf }
            for elem in merkle_proof.siblings.iter() {
                { elem.to_vec() }
            }
        }
    }

    pub(crate) fn query_and_verify_internal(logn: usize, is_sibling: bool) -> Script {
        script! {
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL

            // copy-paste the 4 elements
            //     ABCD -> CDAB -> CDABAB -> ABABCD-> ABABCDCD
            //  -> ABCDCDAB -> ABCDABCD

            OP_2SWAP
            OP_2DUP
            OP_2ROT
            OP_2DUP
            OP_2ROT
            OP_2SWAP

            { CommitmentGadget::commit_qm31() }

            if is_sibling {
                OP_DEPTH OP_1SUB OP_ROLL
                OP_FROMALTSTACK OP_NOTIF OP_SWAP OP_ENDIF
                OP_CAT OP_SHA256

                for _ in 1..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            } else {
                for _ in 0..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            }

            5 OP_ROLL
            OP_EQUALVERIFY
        }
    }

    /// input:
    ///   root_hash
    ///   pos
    ///
    /// output:
    ///   v (qm31 -- 4 elements)
    pub fn query_and_verify(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, false) }
        }
    }

    pub fn query_and_verify_sibling(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, true) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::math::{CM31, M31, QM31};
    use crate::merkle_tree::{MerkleTree, MerkleTreeGadget};
    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    //p2tr relates
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::{
        Amount, OutPoint, Script, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram,
    };
    use bitcoin::transaction::Version;
    use bitcoin::absolute::LockTime;
    use bitcoin_simulator::spending_requirements::{P2TRChecker};
    use std::str::FromStr;


    #[test]
    fn test_merkle_tree_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify(logn);
            println!("MT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                last_layer.push(QM31(
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                ));
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query(pos as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[pos as usize] }
                qm31_equalverify
                OP_TRUE
            };

            //let exec_result = execute_script(script);
            //assert!(exec_result.success);

            // split the script to scriptpubkey and sig 

            let script_pub_key = script! {
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[pos as usize] }
                qm31_equalverify
                OP_TRUE
            }; 

            let script_sig = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
            }; 

            // add p2tr test from bitcoin-simulator 
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let internal_key = UntweakedPublicKey::from(
                bitcoin::secp256k1::PublicKey::from_str(
                    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
                )
                .unwrap(),
            );
    
    
            // let script = script! {
            //     { 1234 } OP_EQUAL
            // };
    
            let taproot_builder = TaprootBuilder::new().add_leaf(0, script_pub_key.clone().into()).unwrap();
            let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();
    
            let witness_program =
                WitnessProgram::p2tr(&secp, internal_key, taproot_spend_info.merkle_root());
    
            let output = TxOut {
                value: Amount::from_sat(1_000_000_000),
                script_pubkey: ScriptBuf::new_witness_program(&witness_program),
            };
    
            let tx = bitcoin::Transaction {
                version: Version(1),
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![output.clone()],
            };
    
            let tx_id = tx.compute_txid();
    
            let mut control_block_bytes = Vec::new();
            taproot_spend_info
                .control_block(&(script_pub_key.clone().into(), LeafVersion::TapScript))
                .unwrap()
                .encode(&mut control_block_bytes)
                .unwrap();
    
            let mut witness = Witness::new();
            witness.push(script_sig.to_bytes());
            witness.push(script_pub_key.to_bytes());
            witness.push(control_block_bytes);
    
            let input = TxIn {
                previous_output: OutPoint::new(tx_id, 0),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness,
            };
    
            let tx2 = bitcoin::Transaction {
                version: Version(1),
                lock_time: LockTime::ZERO,
                input: vec![input.clone()],
                output: vec![],
            };
    
            let res = P2TRChecker::check(&tx2, &[output], 0);
            assert!(res.is_ok());
 

        }
    }

    #[test]
    fn test_merkle_tree_verify_sibling() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify_sibling(logn);

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                last_layer.push(QM31(
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                ));
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query((pos ^ 1) as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[(pos ^ 1) as usize] }
                qm31_equalverify
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
