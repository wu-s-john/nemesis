// merkle_tree.rs
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{borrow::Borrow, collections::HashMap};
use std::fmt::Debug;
use std::hash::Hash;

#[derive(Clone, Debug)]
pub struct LeafIndex<F: Field> {
    pub index: usize,
    pub point: F,
}

#[derive(Clone, Debug)]
pub enum MerkleNode<F: Field, H> {
    Leaf {
        hash: H,
        index: LeafIndex<F>,
        value: F,
    },
    Internal {
        hash: H,
        left: Box<MerkleNode<F, H>>,
        right: Box<MerkleNode<F, H>>,
    },
}

#[derive(Clone, Debug)]
pub struct MerkleProof<F: Field, H> {
    pub root_hash: H,
    pub path: Vec<H>,
    pub leaf_index: LeafIndex<F>,
}

#[derive(Clone)]
pub struct MerkleTree<F: Field, H> {
    pub root: MerkleNode<F, H>,
    pub height: usize,
    pub primitive_root: F,
    pub degree: usize,
    // For proof generation
    nodes_map: HashMap<usize, MerkleNode<F, H>>,
}

pub trait MerkleTreeOperator<F: Field, INCH: TwoToOneCRHScheme>
{
    fn create_tree(
        self: &Self,
        points: Vec<(LeafIndex<F>, F)>,
        primitive_root: F,
        degree: usize,
    ) -> MerkleTree<F, INCH::Output>;

    fn create_proof(&self, tree: &MerkleTree<F, INCH::Output>, leaf_index: &LeafIndex<F>) -> MerkleProof<F, INCH::Output>;
    fn verify_proof(
        &self,
        proof: &MerkleProof<F, INCH::Output>,
        value: F
    ) -> bool;
}

pub struct MerkleTreeOperatorImpl<LCH: CRHScheme, INCH: TwoToOneCRHScheme> {
    leaf_crh_params: LCH::Parameters,
    two_to_one_crh_params: INCH::Parameters,
}


// Implement the MerkleTreeOperator trait for MerkleTreeOperatorImpl
impl<F: Field, LCH, INCH> MerkleTreeOperator<F, INCH> for MerkleTreeOperatorImpl<LCH, INCH>
where
    LCH: CRHScheme<Input = [F], Output = INCH::Output>,
    INCH: TwoToOneCRHScheme + Clone,
    INCH::Output: Clone,
    for<'a> &'a INCH::Output: Borrow<INCH::Input>,
{
    fn create_tree(
        &self,
        points: Vec<(LeafIndex<F>, F)>,
        primitive_root: F,
        degree: usize,
    ) -> MerkleTree<F, INCH::Output> {
        // Create leaf nodes
        let leaves: Vec<MerkleNode<F, INCH::Output>> = points
            .iter()
            .map(|(idx, val)| {
                // Hash the leaf data using CRHScheme
                let leaf_input = vec![idx.point, *val];
                let leaf_hash = LCH::evaluate(&self.leaf_crh_params, leaf_input).unwrap();
                MerkleNode::Leaf {
                    hash: leaf_hash,
                    index: idx.clone(),
                    value: *val,
                }
            })
            .collect();

        let mut nodes_map = HashMap::new();
        for (i, leaf) in leaves.iter().enumerate() {
            nodes_map.insert(i, leaf.clone());
        }

        // Build the Merkle tree bottom-up
        let mut current_level = leaves;
        let mut height = 0;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = Box::new(current_level[i].clone());
                let right = if i + 1 < current_level.len() {
                    Box::new(current_level[i + 1].clone())
                } else {
                    Box::new(current_level[i].clone())
                };
                // Hash the two child hashes using TwoToOneCRHScheme
                
                let combined_hash = INCH::evaluate(
                    &self.two_to_one_crh_params,
                    &left.get_hash(),
                    &right.get_hash(),
                )
                .unwrap();
                let parent = MerkleNode::Internal {
                    hash: combined_hash,
                    left,
                    right,
                };
                next_level.push(parent);
            }
            current_level = next_level;
            height += 1;
        }

        let root = current_level.pop().unwrap();
        MerkleTree {
            root,
            height,
            primitive_root,
            degree,
            nodes_map,
        }
    }

    fn create_proof(&self, tree: &MerkleTree<F, INCH::Output>, leaf_index: &LeafIndex<F>) -> MerkleProof<F, INCH::Output> {
        let mut path = Vec::new();
        let mut index = leaf_index.index;
        let mut current_hash = tree
            .nodes_map
            .get(&index)
            .unwrap()
            .get_hash()
            .clone();

        let mut current_level_nodes = tree.nodes_map.clone();

        for _ in 0..tree.height {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling_node = current_level_nodes.get(&sibling_index);

            let sibling_hash = if let Some(node) = sibling_node {
                node.get_hash()
            } else {
                current_hash.clone()
            };
            path.push(sibling_hash.clone());

            if index % 2 == 0 {
                current_hash = INCH::evaluate(
                    &self.two_to_one_crh_params,
                    &current_hash,
                    &sibling_hash,
                )
                .unwrap();
            } else {
                current_hash = INCH::evaluate(
                    &self.two_to_one_crh_params,
                    &sibling_hash,
                    &current_hash,
                )
                .unwrap();
            }
            index /= 2;
        }

        MerkleProof {
            root_hash: tree.root.get_hash(),
            path,
            leaf_index: leaf_index.clone(),
        }
    }

    fn verify_proof(
        &self,
        proof: &MerkleProof<F, INCH::Output>,
        value: F
    ) -> bool {
        let leaf_input = vec![proof.leaf_index.point, value];
        let mut current_hash = LCH::evaluate(&self.leaf_crh_params, leaf_input).unwrap();
        let mut index = proof.leaf_index.index;

        for sibling_hash in &proof.path {
            if index % 2 == 0 {
                current_hash = INCH::evaluate(
                    &self.two_to_one_crh_params,
                    &current_hash,
                    sibling_hash,
                )
                .unwrap();
            } else {
                current_hash = INCH::evaluate(
                    &self.two_to_one_crh_params,
                    sibling_hash,
                    &current_hash,
                )
                .unwrap();
            }
            index /= 2;
        }

        current_hash == proof.root_hash
    }
}

impl<F: Field, H: Clone> MerkleNode<F, H> {
    pub fn get_hash(&self) -> H {
        match self {
            MerkleNode::Leaf { hash, .. } => hash.clone(),
            MerkleNode::Internal { hash, .. } => hash.clone(),
        }
    }

    pub fn value(&self) -> Option<F> {
        if let MerkleNode::Leaf { value, .. } = self {
            Some(*value)
        } else {
            None
        }
    }
}