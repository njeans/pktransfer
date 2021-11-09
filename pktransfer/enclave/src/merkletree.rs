use data;
use std::vec::Vec;
use sgx_tcrypto::*;
// use sgx_types::SgxResult;

// use std::collections::HashMap;
// use std::untrusted::fs::File;
// use std::io::{self, Read, Write};
//
use sgx_types::*;
// use sgx_tseal::{SgxSealedData};
use sgx_types::marker::ContiguousMemory;

type Hash = Vec<u8>;


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct MerkleTree {
    nodes: Vec<Hash>,
    count_internal_nodes: usize,
    count_leaves: usize,
    leaves: Vec<data::AuditEntry>
}

impl MerkleTree {
    pub fn new() -> MerkleTree
    {
        MerkleTree {
            nodes: Vec::new(),
            count_internal_nodes: 0,
            count_leaves: 0,
            leaves: Vec::new(),
        }
    }

    pub fn build(values: &[data::AuditEntry]) -> SgxResult<MerkleTree>
    {
      let count_leaves = values.len();
      if count_leaves <= 0 {
          return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
      }

      let mut leaves: Vec<Hash> = Vec::new();

      for v in values.iter() {
          let h = match hash_leaf(v) {
              Ok(res) => res,
              Err(err) => {
                  return Err(err);
              }
          };
          leaves.push(h)
      }

      MerkleTree::build_from_leaves(&leaves,values)
    }


    pub fn build_from_leaves(leaves: &[Hash], values: &[data::AuditEntry]) -> SgxResult<MerkleTree> {
        let count_leaves = leaves.len();
        let count_internal_nodes = calculate_internal_nodes_count(count_leaves);
        let mut nodes = vec![Vec::new(); count_internal_nodes + count_leaves];
        nodes[count_internal_nodes..].clone_from_slice(leaves);
        match build_internal_nodes(&mut nodes, count_internal_nodes) {
            Err(err) => {
                return Err(err)
            }
            Ok(_) => ()
        };
        Ok(MerkleTree {
            nodes:  nodes,
            count_internal_nodes: count_internal_nodes,
            count_leaves: count_leaves,
            leaves:values.to_vec(),
        })
    }
}

fn hash_leaf(value: &data::AuditEntry) -> SgxResult<Hash>
{


    match rsgx_sha256_slice(serde_cbor::to_vec(value).unwrap().as_slice()) {
        Err(err) => {
            return Err(err)
        },
        Ok(res) => Ok(res.to_vec())
    }
}


fn calculate_internal_nodes_count(count_leaves: usize) -> usize {
    next_power_of_2(count_leaves) - 1
}

fn build_internal_nodes(nodes: &mut Vec<Hash>, count_internal_nodes: usize) -> SgxError {
    let mut parents = match build_upper_level(&nodes[count_internal_nodes..]){
        Ok(r) => r,
        Err(err) => {
            return Err(err)
        }
    };

    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = upper_level_start + parents.len();
    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1 {
        parents = match build_upper_level(parents.as_slice()){
            Ok(r) => r,
            Err(err) => {
                return Err(err)
            }
        };

        upper_level_start -= parents.len();
        upper_level_end = upper_level_start + parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }

    nodes[0] = parents.remove(0);
    Ok(())
}

fn build_upper_level(nodes: &[Hash]) -> SgxResult<Vec<Hash>>
{
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            match hash_internal_node(&nodes[i], Some(&nodes[i + 1])) {
                Ok(r) => {
                    row.push(r);
                },
                Err(err) => {
                    return Err(err);
                }
            };
            i += 2;
        } else {
            match hash_internal_node(&nodes[i], None) {
                Ok(r) => {
                    row.push(r)
                },
                Err(err) => {
                    return Err(err)
                }
            };
            i += 1;
        }
    }

    if row.len() > 1 && row.len() % 2 != 0 {
        let last_node = row.last().unwrap().clone();
        row.push(last_node);
    }

    Ok(row)
}

fn hash_internal_node(left: &Hash, right: Option<&Hash>) -> SgxResult<Hash>
{
    let r  = match right {
        Some(res) => res.as_slice(),
        None => left.as_slice()
    };
    let comb = [left.clone().as_slice(),r].concat();

    match rsgx_sha256_slice(comb.as_slice()) {
        Err(err) => {
            return Err(err)
        },
        Ok(res) => Ok(res.to_vec())
    }
}



fn next_power_of_2(n: usize) -> usize {
    let mut v = n;
    v -= 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v += 1;
    v
}

pub trait AsBytes {
    /// Converts value into the byte slice.
    fn as_bytes(&self) -> &[u8];
}

// impl AsBytes for data::AuditEntry {
//     fn as_bytes(&self) -> &[u8] {
//         serde_cbor::to_vec(self).unwrap().as_slice()
//     }
// }
