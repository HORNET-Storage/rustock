/// RSKIP107-compatible trie node: binary radix-2 trie with path compression.
///
/// Each node has:
/// - `shared_path`: compressed path prefix (bits shared by all keys in this sub-trie)
/// - `left` / `right`: child references (bit 0 / bit 1)
/// - `value`: inline data for this key, or None
/// - `value_hash`: keccak256 of the value
/// - `children_size`: aggregate size of child sub-trees (VarInt-encoded in serialization)
use alloy_primitives::B256;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use sha3::{Digest, Keccak256};
use crate::path::TrieKeySlice;
use crate::shared_path;
use crate::store::TrieStore;
use crate::varint;

const MAX_EMBEDDED_NODE_SIZE: usize = 44;

pub(crate) fn keccak(data: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(data))
}

/// The empty trie hash is `keccak256(RLP(""))` = `keccak256([0x80])`.
pub fn empty_trie_hash() -> B256 {
    keccak(&[0x80])
}

/// Reference to a child node — either in-memory, by hash, or empty.
///
/// The in-memory variant is an `Arc` and not a `Box` for one reason, and
/// it is the difference between a block costing linear and quadratic time.
/// A `Box` is a unique owner, so cloning one has to clone what it points
/// at, and `TrieNode` holds two more `NodeRef`s -- so the copy recurses
/// through the entire in-memory subtree. `internal_put` clones twice per
/// level of its descent (the child it goes into, and the sibling it
/// carries over), and a block's puts leave `Node` behind them where they
/// found `Hash`. Put number k therefore copied everything puts 1..k-1 had
/// built. Measured: per-put cost doubled with every doubling of the puts
/// in a block.
///
/// `Arc::clone` is an atomic increment instead, and sharing is sound
/// because a `TrieNode` is immutable once constructed -- `put` and
/// `delete` return new nodes rather than modifying old ones, and the two
/// fields that do change after construction (`saved` and `hash_cache`)
/// are both interior-mutable and both monotonic, so two owners of the
/// same node cannot disagree about them.
///
/// See `crates/trie/examples/put_scaling.rs`, which measures the shape.
#[derive(Clone, Debug)]
pub enum NodeRef {
    Empty,
    Hash(B256),
    Node(Arc<TrieNode>),
}

/// What [`NodeRef::try_resolve`] found.
///
/// The distinction `Option` cannot make: `Absent` is a well-formed trie that
/// ends here, `Missing` is a trie that refers to a node the store does not
/// hold.
// No PartialEq: TrieNode does not implement it, and comparing two resolutions
// structurally is not a thing a caller should want -- match on the variant.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// The node is here.
    Found(Arc<TrieNode>),
    /// The trie ends here. Nothing is wrong.
    Absent,
    /// The trie refers to this hash and the store cannot produce a node for
    /// it. The store is incomplete -- collected, pruned, or damaged.
    Missing(B256),
}

impl NodeRef {
    pub fn is_empty(&self) -> bool {
        matches!(self, NodeRef::Empty)
    }

    /// Resolves the node, distinguishing "the trie ends here" from "the trie
    /// says there is a node here and the store does not have it".
    ///
    /// [`resolve`](Self::resolve) answers both with `None`, which is right when
    /// reading a store filled from the network -- a peer may simply not have
    /// sent it yet. It is wrong when a node reads its **own** store to execute
    /// a block: there, a referenced node that is absent means the trie is
    /// incomplete, and reporting it as an empty account is how mainnet
    /// 2026-09-23 surfaced as `NonceTooHigh { state: 0 }` instead of as the
    /// missing state it was.
    ///
    /// Costs nothing extra: `resolve` already performs the lookup that tells
    /// the two apart and discards the answer with `?`.
    pub fn try_resolve(&self, store: &dyn TrieStore) -> Resolution {
        match self {
            NodeRef::Empty => Resolution::Absent,
            NodeRef::Node(n) => Resolution::Found(Arc::clone(n)),
            NodeRef::Hash(h) => match store.get(h.as_slice()) {
                // Unreadable bytes are as missing as absent ones: the store
                // holds something under that hash, but nothing that can be
                // walked, so the trie is incomplete either way.
                Some(data) => match TrieNode::try_from_message(&data, store) {
                    Some(node) => Resolution::Found(Arc::new(node)),
                    None => Resolution::Missing(*h),
                },
                None => Resolution::Missing(*h),
            },
        }
    }

    /// Resolves the node, loading from store if only a hash is available.
    pub fn resolve(&self, store: &dyn TrieStore) -> Option<Arc<TrieNode>> {
        match self {
            NodeRef::Empty => None,
            NodeRef::Node(n) => Some(Arc::clone(n)),
            NodeRef::Hash(h) => {
                // Unresolvable and unparseable are the same answer here. A
                // store can hold bytes a peer supplied, and a node nobody can
                // read is a node that is not there.
                let data = store.get(h.as_slice())?;
                TrieNode::try_from_message(&data, store).map(Arc::new)
            }
        }
    }

    /// Resolve by consuming the reference.
    ///
    /// Unlike [`Self::resolve_owned`] this takes `self`, so when the
    /// reference is the only owner of its `Arc` the node is moved out
    /// rather than copied -- which is the case on the delete path, where
    /// the node being unwrapped was built one call ago.
    pub fn into_owned(self, store: &dyn TrieStore) -> Option<TrieNode> {
        match self {
            NodeRef::Empty => None,
            NodeRef::Node(n) => {
                Some(Arc::try_unwrap(n).unwrap_or_else(|shared| (*shared).clone()))
            }
            NodeRef::Hash(h) => {
                let data = store.get(h.as_slice())?;
                TrieNode::try_from_message(&data, store)
            }
        }
    }

    /// Like [`Self::resolve`], but hands back an owned node.
    ///
    /// Prefer `resolve`. This one has to copy when the child is already in
    /// memory, and copying a `NodeRef::Node` copies its whole subtree --
    /// which is the cost the `Arc` exists to avoid. It is here for the few
    /// callers that put the node into a structure of their own and cannot
    /// share it. Never use it on a put or get path.
    ///
    /// The copy is skipped when this reference is the only owner, which is
    /// the common case of a node just read from the store.
    pub fn resolve_owned(&self, store: &dyn TrieStore) -> Option<TrieNode> {
        self.resolve(store).map(|n| Arc::try_unwrap(n).unwrap_or_else(|shared| (*shared).clone()))
    }

    pub fn get_hash(&self, store: &dyn TrieStore) -> Option<B256> {
        match self {
            NodeRef::Empty => None,
            NodeRef::Hash(h) => Some(*h),
            NodeRef::Node(n) => Some(n.compute_hash(store)),
        }
    }

    fn is_embeddable(&self, store: &dyn TrieStore) -> bool {
        match self {
            NodeRef::Node(n) => n.is_embeddable(store),
            _ => false,
        }
    }

    fn serialized_length(&self, store: &dyn TrieStore) -> usize {
        if self.is_empty() {
            return 0;
        }
        if self.is_embeddable(store) {
            if let NodeRef::Node(n) = self {
                return 1 + n.message_length(store);
            }
        }
        32 // keccak256 hash
    }

    fn serialize_into(&self, out: &mut Vec<u8>, store: &dyn TrieStore) {
        match self {
            NodeRef::Empty => {}
            NodeRef::Node(n) if n.is_embeddable(store) => {
                let msg = n.to_message(store);
                out.push(msg.len() as u8);
                out.extend_from_slice(&msg);
            }
            _ => {
                if let Some(h) = self.get_hash(store) {
                    out.extend_from_slice(h.as_slice());
                }
            }
        }
    }

    /// The sub-tree size as defined by RSKIP107: serialized node + children_size + external_value_length.
    pub(crate) fn reference_size(&self, store: &dyn TrieStore) -> u64 {
        match self {
            NodeRef::Empty => 0,
            NodeRef::Node(n) => {
                let external_val_len = if n.has_long_value() { n.value_length() as u64 } else { 0 };
                n.children_size + external_val_len + n.message_length(store) as u64
            }
            NodeRef::Hash(h) => {
                if let Some(data) = store.get(h.as_slice()) {
                    let Some(node) = TrieNode::try_from_message(&data, store) else {
                        return 0;
                    };
                    let external_val_len = if node.has_long_value() { node.value_length() as u64 } else { 0 };
                    node.children_size + external_val_len + data.len() as u64
                } else {
                    0
                }
            }
        }
    }
}

/// Orchid hash of a child reference (rskj `NodeReference.getHashOrchid`):
/// `None` for empty references.
fn orchid_child_hash(child: &NodeRef, is_secure: bool, store: &dyn TrieStore) -> Option<B256> {
    let node = child.resolve(store)?;
    Some(node.compute_hash_orchid(is_secure, store))
}

/// The longest shared path any unitrie node can have.
///
/// The longest key the trie holds is a storage slot: an account key
/// (1 prefix + 10 secure + 20 address) then 1 storage prefix, 10 secure and
/// up to 32 slot bytes -- 74 bytes, 592 bits. This is comfortably above that
/// and far below the point where declaring a length becomes an amplification.
const MAX_SHARED_PATH_BITS: usize = 1024;

/// A bounds-checked walk over a node message.
///
/// Returning `None` where the plain indexing would have panicked is the whole
/// point: these bytes can come from a peer.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn varint(&mut self) -> Option<u64> {
        let first = *self.data.get(self.pos)?;
        let width = match first {
            0..=252 => 1,
            253 => 3,
            254 => 5,
            _ => 9,
        };
        let bytes = self.take(width)?;
        Some(match width {
            1 => first as u64,
            3 => u16::from_le_bytes(bytes[1..3].try_into().ok()?) as u64,
            5 => u32::from_le_bytes(bytes[1..5].try_into().ok()?) as u64,
            _ => u64::from_le_bytes(bytes[1..9].try_into().ok()?),
        })
    }
}

#[derive(Debug)]
pub struct TrieNode {
    pub shared_path: TrieKeySlice,
    pub value: Option<Vec<u8>>,
    pub value_hash: Option<B256>,
    /// Length of a value stored outside the node, when the value itself is
    /// not in hand.
    ///
    /// The length is written into the node's message and so is part of its
    /// hash. Without it, a node parsed from a store that does not hold its
    /// long value looks like a node with no value at all: a different length,
    /// a different hash, a different subtree size. Reading it from the message
    /// means such a node still measures correctly, which is what lets a
    /// snapshot witness carry node messages without dragging their values
    /// along.
    pub long_value_len: Option<u32>,
    pub left: NodeRef,
    pub right: NodeRef,
    pub children_size: u64,
    /// Whether this node is already in the store.
    ///
    /// Interior-mutable because `collect_for_save` reaches children through
    /// an `Arc`, which cannot hand out `&mut`. It is only ever set, never
    /// cleared, so two owners of a shared node cannot disagree: the worst a
    /// race does is let both walk the subtree, and writing the same
    /// content-addressed bytes twice is harmless.
    saved: AtomicBool,
    /// Memoised result of `compute_hash`.
    ///
    /// Safe to cache unconditionally: a TrieNode's content is immutable once
    /// constructed. `put`/`delete` return *new* nodes rather than mutating in
    /// place, and the only `&mut self` method is `save`, which merely sets the
    /// `saved` flag. A cached hash therefore cannot go stale.
    ///
    /// This matters because hashing is not local: `to_message` needs each
    /// in-memory child's hash (`NodeRef::get_hash` -> `compute_hash`), so
    /// hashing a node recurses through its entire dirty subtree. Without a
    /// cache that cascade repeats on every call. Profiling the syncing node
    /// showed keccak at 23% of CPU and 1064 compute_hash calls per block, on
    /// blocks carrying only ~2 transactions.
    hash_cache: OnceLock<B256>,
}

/// Hand-written because `saved` is an `AtomicBool`, which is not `Clone`.
///
/// Both of the interior-mutable fields are carried over, and both are
/// sound to carry: a clone has the same content as its original, so it
/// hashes the same and -- the store being content-addressed -- is already
/// in the store if the original was.
impl Clone for TrieNode {
    fn clone(&self) -> Self {
        Self {
            shared_path: self.shared_path.clone(),
            value: self.value.clone(),
            value_hash: self.value_hash,
            long_value_len: self.long_value_len,
            left: self.left.clone(),
            right: self.right.clone(),
            children_size: self.children_size,
            saved: AtomicBool::new(self.saved.load(Ordering::Acquire)),
            hash_cache: self.hash_cache.clone(),
        }
    }
}

impl TrieNode {
    pub fn empty() -> Self {
        Self {
            shared_path: TrieKeySlice::empty(),
            value: None,
            value_hash: None,
            left: NodeRef::Empty,
            right: NodeRef::Empty,
            children_size: 0,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        }
    }

    /// Builds an in-memory node from explicit parts (orchid conversion only —
    /// these nodes are hashed, never saved).
    pub(crate) fn from_parts(
        shared_path: TrieKeySlice,
        value: Option<Vec<u8>>,
        value_hash: Option<B256>,
        left: NodeRef,
        right: NodeRef,
    ) -> Self {
        Self { shared_path, value, value_hash, left, right, children_size: 0, saved: AtomicBool::new(false), long_value_len: None, hash_cache: OnceLock::new() }
    }

    pub fn new_leaf(shared_path: TrieKeySlice, value: Vec<u8>) -> Self {
        let value_hash = Some(keccak(&value));
        Self {
            shared_path,
            value: Some(value),
            value_hash,
            left: NodeRef::Empty,
            right: NodeRef::Empty,
            children_size: 0,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn is_empty_trie(&self) -> bool {
        self.value.is_none()
            && self.long_value_len.is_none()
            && self.left.is_empty()
            && self.right.is_empty()
    }

    pub fn is_terminal(&self) -> bool {
        self.left.is_empty() && self.right.is_empty()
    }

    pub fn value_length(&self) -> usize {
        match &self.value {
            Some(v) => v.len(),
            None => self.long_value_len.unwrap_or(0) as usize,
        }
    }

    pub fn has_long_value(&self) -> bool {
        self.value_length() > 32
    }

    pub(crate) fn get_value_hash(&self) -> B256 {
        self.value_hash.unwrap_or_else(|| {
            self.value.as_ref().map_or(B256::ZERO, |v| keccak(v))
        })
    }

    pub fn is_embeddable(&self, store: &dyn TrieStore) -> bool {
        self.is_terminal() && self.message_length(store) <= MAX_EMBEDDED_NODE_SIZE
    }

    pub fn message_length(&self, store: &dyn TrieStore) -> usize {
        let lshared = self.shared_path.length();
        let has_long_val = self.has_long_value();
        let vlen = self.value_length();

        1 // flags
        + shared_path::serialized_length(lshared)
        + self.left.serialized_length(store)
        + self.right.serialized_length(store)
        + if self.is_terminal() { 0 } else { varint::varint_size(self.children_size) }
        + if has_long_val { 32 + 3 } else { vlen }
    }

    /// Serializes this node to the RSKIP107 wire format.
    pub fn to_message(&self, store: &dyn TrieStore) -> Vec<u8> {
        let cap = self.message_length(store);
        let mut out = Vec::with_capacity(cap);

        let has_long_val = self.has_long_value();

        let mut flags: u8 = 0b0100_0000; // version 01
        if has_long_val {
            flags |= 0b0010_0000;
        }
        if !self.shared_path.is_empty() {
            flags |= 0b0001_0000;
        }
        if !self.left.is_empty() {
            flags |= 0b0000_1000;
        }
        if !self.right.is_empty() {
            flags |= 0b0000_0100;
        }
        if self.left.is_embeddable(store) {
            flags |= 0b0000_0010;
        }
        if self.right.is_embeddable(store) {
            flags |= 0b0000_0001;
        }
        out.push(flags);

        shared_path::serialize(&self.shared_path, &mut out);

        self.left.serialize_into(&mut out, store);
        self.right.serialize_into(&mut out, store);

        if !self.is_terminal() {
            out.extend_from_slice(&varint::encode_varint(self.children_size));
        }

        if has_long_val {
            out.extend_from_slice(self.get_value_hash().as_slice());
            let vlen = self.value_length() as u32;
            out.push((vlen >> 16) as u8);
            out.push((vlen >> 8) as u8);
            out.push(vlen as u8);
        } else if let Some(ref v) = self.value {
            out.extend_from_slice(v);
        }

        out
    }

    /// Deserializes a node from the RSKIP107 wire format.
    ///
    /// Panics on a malformed message. Use [`TrieNode::try_from_message`] for
    /// bytes that came from anywhere but our own database -- a peer's, above
    /// all, where a malformed message is an attack rather than corruption.
    pub fn from_message(data: &[u8], store: &dyn TrieStore) -> Self {
        Self::try_from_message(data, store).expect("malformed trie node message")
    }

    /// Deserializes a node from the RSKIP107 wire format, returning `None`
    /// rather than panicking if the bytes do not describe a node.
    ///
    /// Every read is bounds-checked, so any byte string at all is safe to
    /// pass: a node arriving over the wire is exactly as trustworthy as
    /// whoever sent it.
    pub fn try_from_message(data: &[u8], store: &dyn TrieStore) -> Option<Self> {
        let mut r = Reader { data, pos: 0 };

        let flags = r.byte()?;
        let has_long_val = flags & 0b0010_0000 != 0;
        let shared_prefix_present = flags & 0b0001_0000 != 0;
        let left_present = flags & 0b0000_1000 != 0;
        let right_present = flags & 0b0000_0100 != 0;
        let left_embedded = flags & 0b0000_0010 != 0;
        let right_embedded = flags & 0b0000_0001 != 0;

        let shared_path = if shared_prefix_present {
            let first = r.byte()? as usize;
            let lshared = if first <= 31 {
                first + 1
            } else if first <= 254 {
                first + 128
            } else {
                r.varint()? as usize
            };
            // A shared path longer than any key the trie can hold is not a
            // trie node. Without this a peer could declare a huge one and have
            // the parser expand it eightfold -- one bit per byte -- from a
            // message the transport was happy to carry.
            if lshared > MAX_SHARED_PATH_BITS {
                return None;
            }
            let encoded = r.take(crate::path::encoded_len(lshared))?;
            TrieKeySlice::from_encoded(encoded, lshared)
        } else {
            TrieKeySlice::empty()
        };

        let mut child = |present: bool, embedded: bool| -> Option<NodeRef> {
            if !present {
                return Some(NodeRef::Empty);
            }
            if embedded {
                let len = r.byte()? as usize;
                let body = r.take(len)?;
                Some(NodeRef::Node(Arc::new(TrieNode::try_from_message(body, store)?)))
            } else {
                Some(NodeRef::Hash(B256::from_slice(r.take(32)?)))
            }
        };
        let left = child(left_present, left_embedded)?;
        let right = child(right_present, right_embedded)?;

        let children_size =
            if left_present || right_present { r.varint()? } else { 0 };

        let mut long_value_len = None;
        let (value, value_hash) = if has_long_val {
            let vh = B256::from_slice(r.take(32)?);
            let len = r.take(3)?;
            let vlen =
                ((len[0] as u32) << 16) | ((len[1] as u32) << 8) | (len[2] as u32);
            let val = store.get(vh.as_slice());
            // A stored value of the wrong length is not this node's value: the
            // length is part of the message and so part of the node's hash.
            if val.as_ref().is_some_and(|v| v.len() != vlen as usize) {
                return None;
            }
            long_value_len = Some(vlen);
            (val, Some(vh))
        } else if r.pos < data.len() {
            let v = data[r.pos..].to_vec();
            let vh = keccak(&v);
            (Some(v), Some(vh))
        } else {
            (None, None)
        };

        Some(Self {
            shared_path,
            value,
            value_hash,
            left,
            right,
            children_size,
            saved: AtomicBool::new(false),
            long_value_len,
            hash_cache: OnceLock::new(),
        })
    }

    /// Computes the Keccak-256 hash of this node's serialized message.
    pub fn compute_hash(&self, store: &dyn TrieStore) -> B256 {
        if self.is_empty_trie() {
            return empty_trie_hash();
        }
        *self
            .hash_cache
            .get_or_init(|| keccak(&self.to_message(store)))
    }

    /// Serializes this node in the pre-RSKIP107 ("Orchid") wire format
    /// (rskj `Trie.toMessageOrchid`). Used for the tx/receipts trie roots in
    /// block headers before RSKIP126 activated.
    ///
    /// Layout: arity(1) | flags(1) | child-bits(u16 BE) | lshared-in-bits(u16 BE)
    /// | encoded path | left orchid hash | right orchid hash | value-or-valueHash.
    pub fn to_message_orchid(&self, is_secure: bool, store: &dyn TrieStore) -> Vec<u8> {
        let lshared = self.shared_path.length();
        let has_long_val = self.has_long_value();
        let left_hash = orchid_child_hash(&self.left, is_secure, store);
        let right_hash = orchid_child_hash(&self.right, is_secure, store);

        let mut bits = 0u16;
        if left_hash.is_some() {
            bits |= 0b01;
        }
        if right_hash.is_some() {
            bits |= 0b10;
        }

        let mut out = Vec::new();
        out.push(2); // ARITY
        let mut flags = 0u8;
        if is_secure {
            flags |= 1;
        }
        if has_long_val {
            flags |= 2;
        }
        out.push(flags);
        out.extend_from_slice(&bits.to_be_bytes());
        out.extend_from_slice(&(lshared as u16).to_be_bytes());

        if lshared > 0 {
            out.extend_from_slice(&self.shared_path.encode());
        }
        if let Some(h) = left_hash {
            out.extend_from_slice(h.as_slice());
        }
        if let Some(h) = right_hash {
            out.extend_from_slice(h.as_slice());
        }

        if self.value_length() > 0 {
            if has_long_val {
                out.extend_from_slice(self.get_value_hash().as_slice());
            } else if let Some(ref v) = self.value {
                out.extend_from_slice(v);
            }
        }

        out
    }

    /// Keccak-256 of the Orchid serialization (rskj `Trie.getHashOrchid`).
    pub fn compute_hash_orchid(&self, is_secure: bool, store: &dyn TrieStore) -> B256 {
        if self.is_empty_trie() {
            return empty_trie_hash();
        }
        keccak(&self.to_message_orchid(is_secure, store))
    }

    /// Retrieves the value at the given key, or None.
    pub fn get(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> Option<Vec<u8>> {
        let node = self.find(key, store)?;
        node.value.clone()
    }

    /// Every node on the path from this one to `key`, **leaf first, root last**.
    ///
    /// rskj `Trie.findNodes`. The ordering is not the obvious one and is worth
    /// stating: each level appends *itself* after recursing into its child, so
    /// the caller receives the deepest node first and this node last.
    ///
    /// ```text
    ///   rskj:  subnodes = child.findNodes(...);  subnodes.add(this);
    ///                                            ^^^^^^^^^^^^^^^^^ after
    /// ```
    ///
    /// `None` when the key is not in the trie -- the same condition under which
    /// [`TrieNode::find`] returns `None`, so a proof is never half-built.
    pub fn nodes_on_path(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> Option<Vec<TrieNode>> {
        if self.shared_path.length() > key.length() {
            return None;
        }

        let common = key.common_path(&self.shared_path);
        if common.length() < self.shared_path.length() {
            return None;
        }

        if common.length() == key.length() {
            return Some(vec![self.clone()]);
        }

        let bit = key.get(common.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = child_ref.resolve(store)?;
        let sub_key = key.slice(common.length() + 1, key.length());
        let mut subnodes = child.nodes_on_path(&sub_key, store)?;
        subnodes.push(self.clone());
        Some(subnodes)
    }

    /// Every node from this one toward `key`, **leaf first, root last**,
    /// whether or not the trie holds the key.
    ///
    /// Where it does, this is [`nodes_on_path`](Self::nodes_on_path). Where it
    /// does not, the path runs down to the node at which the key leaves the
    /// trie, and that node shows it on its own terms: its shared path parts
    /// from the key's, or the key ends inside it, or the child the key would
    /// take is empty, or the key ends at it and it holds no value. The nodes
    /// above it tie it to the root, which is what makes the path a proof of
    /// absence.
    ///
    /// `Err` with the hash the store could not produce when a reference on the
    /// way cannot be followed: an incomplete store proves nothing either way,
    /// and answering as though the key were absent would be a false proof.
    pub fn try_nodes_toward(
        &self,
        key: &TrieKeySlice,
        store: &dyn TrieStore,
    ) -> Result<Vec<TrieNode>, B256> {
        let common = key.common_path(&self.shared_path);
        if common.length() < self.shared_path.length() || common.length() == key.length() {
            return Ok(vec![self.clone()]);
        }

        let bit = key.get(common.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = match child_ref.try_resolve(store) {
            Resolution::Found(c) => c,
            Resolution::Absent => return Ok(vec![self.clone()]),
            Resolution::Missing(h) => return Err(h),
        };
        let sub_key = key.slice(common.length() + 1, key.length());
        let mut nodes = child.try_nodes_toward(&sub_key, store)?;
        nodes.push(self.clone());
        Ok(nodes)
    }

    /// Like [`get`](Self::get), but says which node was missing instead of
    /// answering "no value" when the trie is incomplete.
    ///
    /// `Ok(None)` means the key is genuinely not in the trie. `Err(hash)` means
    /// the walk reached a reference the store could not resolve, and the answer
    /// is unknown rather than absent.
    pub fn try_get(
        &self,
        key: &TrieKeySlice,
        store: &dyn TrieStore,
    ) -> Result<Option<Vec<u8>>, B256> {
        Ok(self.try_find(key, store)?.and_then(|n| n.value.clone()))
    }

    /// The strict counterpart of [`find`](Self::find); see
    /// [`try_get`](Self::try_get).
    pub fn try_find(
        &self,
        key: &TrieKeySlice,
        store: &dyn TrieStore,
    ) -> Result<Option<TrieNode>, B256> {
        if self.shared_path.length() > key.length() {
            return Ok(None);
        }

        let common = key.common_path(&self.shared_path);
        if common.length() < self.shared_path.length() {
            return Ok(None);
        }

        if common.length() == key.length() {
            return Ok(Some(self.clone()));
        }

        let bit = key.get(common.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = match child_ref.try_resolve(store) {
            Resolution::Found(c) => c,
            // The trie ends here: the key is not in it, which is an answer.
            Resolution::Absent => return Ok(None),
            // The trie does not end here; the store just cannot follow it.
            Resolution::Missing(h) => return Err(h),
        };
        let sub_key = key.slice(common.length() + 1, key.length());
        child.try_find(&sub_key, store)
    }

    fn find(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> Option<TrieNode> {
        if self.shared_path.length() > key.length() {
            return None;
        }

        let common = key.common_path(&self.shared_path);
        if common.length() < self.shared_path.length() {
            return None;
        }

        if common.length() == key.length() {
            return Some(self.clone());
        }

        let bit = key.get(common.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = child_ref.resolve(store)?;
        let sub_key = key.slice(common.length() + 1, key.length());
        child.find(&sub_key, store)
    }

    /// Inserts or updates a value at the given key. Returns the new root node.
    pub fn put(&self, key: &TrieKeySlice, value: &[u8], store: &dyn TrieStore) -> TrieNode {
        let key_slice = key.clone();
        match self.internal_put(&key_slice, Some(value), false, store) {
            Some(node) => node,
            None => TrieNode::empty(),
        }
    }

    /// Deletes the value at the given key. Returns the new root node.
    pub fn delete(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> TrieNode {
        let key_slice = key.clone();
        match self.put_impl(&key_slice, None, false, store) {
            Some(node) => node,
            None => TrieNode::empty(),
        }
    }

    /// Deletes the node at the given key together with its whole subtree
    /// (rskj `Trie.deleteRecursive`). Used to remove an account and all its
    /// storage/code/marker descendants in one operation.
    pub fn delete_recursive(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> TrieNode {
        let key_slice = key.clone();
        match self.put_impl(&key_slice, None, true, store) {
            Some(node) => node,
            None => TrieNode::empty(),
        }
    }

    fn put_impl(
        &self,
        key: &TrieKeySlice,
        value: Option<&[u8]>,
        is_recursive_delete: bool,
        store: &dyn TrieStore,
    ) -> Option<TrieNode> {
        let trie = self.internal_put(key, value, is_recursive_delete, store)?;

        // Coalescing: if deleting and result has exactly one child and no value, merge.
        if value.is_some() {
            return Some(trie);
        }

        if trie.is_empty_trie() {
            return None;
        }

        if trie.value.is_some() {
            return Some(trie);
        }

        // both present or both empty → no coalescing
        if trie.left.is_empty() == trie.right.is_empty() {
            return Some(trie);
        }

        let shared_path = trie.shared_path.clone();
        let (child, implicit_bit) = if !trie.left.is_empty() {
            (trie.left.into_owned(store)?, 0u8)
        } else {
            (trie.right.into_owned(store)?, 1u8)
        };

        let new_path = shared_path.rebuild_shared_path(implicit_bit, &child.shared_path);
        Some(TrieNode {
            shared_path: new_path,
            value: child.value,
            value_hash: child.value_hash,
            left: child.left,
            right: child.right,
            children_size: child.children_size,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        })
    }

    fn internal_put(
        &self,
        key: &TrieKeySlice,
        value: Option<&[u8]>,
        is_recursive_delete: bool,
        store: &dyn TrieStore,
    ) -> Option<TrieNode> {
        // Normalize: empty value = deletion
        let value = match value {
            Some([]) => None,
            other => other,
        };

        let common = key.common_path(&self.shared_path);

        if common.length() < self.shared_path.length() {
            // Path diverges — need to split this node
            if value.is_none() {
                return Some(self.clone()); // deleting non-existent key
            }
            let split = self.split(&common, store);
            return split.put_impl(key, value, is_recursive_delete, store);
        }

        // Shared path is fully consumed
        if self.shared_path.length() >= key.length() {
            // This is the target node
            if self.value.as_deref() == value {
                return Some(self.clone()); // no change
            }

            if is_recursive_delete {
                // rskj `new Trie(store, sharedPath, null)`: the whole subtree
                // (children included) is dropped; put_impl collapses the
                // now-empty node to None so the parent unlinks it.
                return Some(TrieNode {
                    shared_path: self.shared_path.clone(),
                    value: None,
                    value_hash: None,
                    left: NodeRef::Empty,
                    right: NodeRef::Empty,
                    children_size: 0,
                    saved: AtomicBool::new(false),
                    long_value_len: None,
            hash_cache: OnceLock::new(),
                });
            }

            if Self::is_empty_trie_params(value, &self.left, &self.right) {
                return None;
            }

            let vh = value.map(keccak);
            return Some(TrieNode {
                shared_path: self.shared_path.clone(),
                value: value.map(|v| v.to_vec()),
                value_hash: vh,
                left: self.left.clone(),
                right: self.right.clone(),
                children_size: self.children_size,
                saved: AtomicBool::new(false),
                long_value_len: None,
            hash_cache: OnceLock::new(),
            });
        }

        if self.is_empty_trie() {
            // Replace empty trie with a new leaf
            let vh = value.map(keccak);
            return Some(TrieNode {
                shared_path: key.clone(),
                value: value.map(|v| v.to_vec()),
                value_hash: vh,
                left: NodeRef::Empty,
                right: NodeRef::Empty,
                children_size: 0,
                saved: AtomicBool::new(false),
                long_value_len: None,
            hash_cache: OnceLock::new(),
            });
        }

        // Navigate to child
        let bit = key.get(self.shared_path.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = child_ref.resolve(store).unwrap_or_else(|| Arc::new(TrieNode::empty()));

        let sub_key = key.slice(self.shared_path.length() + 1, key.length());
        let new_child_opt = child.put_impl(&sub_key, value, is_recursive_delete, store);

        // None means the child sub-tree was fully deleted
        let new_ref = match new_child_opt {
            Some(c) => NodeRef::Node(Arc::new(c)),
            None => NodeRef::Empty,
        };

        let new_cs = self.children_size
            .saturating_sub(child_ref.reference_size(store))
            + new_ref.reference_size(store);

        let (new_left, new_right) = if bit == 0 {
            (new_ref, self.right.clone())
        } else {
            (self.left.clone(), new_ref)
        };

        if Self::is_empty_trie_params(self.value.as_deref(), &new_left, &new_right) {
            return None;
        }

        Some(TrieNode {
            shared_path: self.shared_path.clone(),
            value: self.value.clone(),
            value_hash: self.value_hash,
            left: new_left,
            right: new_right,
            children_size: new_cs,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        })
    }

    fn split(&self, common_path: &TrieKeySlice, store: &dyn TrieStore) -> TrieNode {
        let common_len = common_path.length();
        let new_child_path = self.shared_path.slice(common_len + 1, self.shared_path.length());
        let new_child = TrieNode {
            shared_path: new_child_path,
            value: self.value.clone(),
            value_hash: self.value_hash,
            left: self.left.clone(),
            right: self.right.clone(),
            children_size: self.children_size,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        };

        let child_ref = NodeRef::Node(Arc::new(new_child));
        let bit = self.shared_path.get(common_len);

        let cs = child_ref.reference_size(store);
        let (new_left, new_right) = if bit == 0 {
            (child_ref, NodeRef::Empty)
        } else {
            (NodeRef::Empty, child_ref)
        };

        TrieNode {
            shared_path: common_path.clone(),
            value: None,
            value_hash: None,
            left: new_left,
            right: new_right,
            children_size: cs,
            saved: AtomicBool::new(false),
            long_value_len: None,
            hash_cache: OnceLock::new(),
        }
    }

    fn is_empty_trie_params(value: Option<&[u8]>, left: &NodeRef, right: &NodeRef) -> bool {
        value.is_none() && left.is_empty() && right.is_empty()
    }

    /// Recursively saves this node (and its children) to the store.
    /// Persist this node and everything dirty beneath it.
    ///
    /// The whole subtree is collected first and written in **one** call.
    /// A block rewrites roughly 6,900 nodes -- every node on the path
    /// from each touched account up to the root -- and handing them over
    /// singly makes the store pay its per-write cost that many times. For
    /// an append-only store that cost includes reserving space in a
    /// frontier shared between threads, which is the part that has to be
    /// serialised; one batch reserves once.
    pub fn save(&mut self, store: &dyn TrieStore, is_root: bool) {
        let mut batch = Vec::new();
        self.collect_for_save(store, is_root, &mut batch);
        if !batch.is_empty() {
            store.put_many(&batch);
        }
    }

    /// The body of [`Self::save`], accumulating instead of writing.
    ///
    /// Reads still go to the store while this runs -- `to_message` and
    /// `is_embeddable` consult it -- but only for nodes that are already
    /// there. Everything this produces is in memory and is reachable
    /// through the node graph, so nothing in the batch is needed to build
    /// the rest of it.
    fn collect_for_save(
        &self,
        store: &dyn TrieStore,
        is_root: bool,
        batch: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        if self.saved.load(Ordering::Acquire) {
            return;
        }

        // Children first, so a parent's message is built from children
        // whose hashes are settled.
        if let NodeRef::Node(child) = &self.left {
            child.collect_for_save(store, false, batch);
        }
        if let NodeRef::Node(child) = &self.right {
            child.collect_for_save(store, false, batch);
        }

        // A long value lives outside its node, under its own hash.
        if self.has_long_value() {
            if let Some(ref v) = self.value {
                let vh = self.get_value_hash();
                batch.push((vh.as_slice().to_vec(), v.clone()));
            }
        }

        // Embeddable non-root nodes are not stored independently.
        if self.is_embeddable(store) && !is_root {
            self.saved.store(true, Ordering::Release);
            return;
        }

        // Serialise once. `compute_hash` calls `to_message` internally, so
        // calling both built the message twice -- and because serialisation
        // recurses into in-memory children, that doubled the work for the whole
        // dirty subtree beneath this node, not merely this node.
        let msg = self.to_message(store);
        let hash = *self.hash_cache.get_or_init(|| keccak(&msg));
        batch.push((hash.as_slice().to_vec(), msg));
        self.saved.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryTrieStore;
    use std::sync::Arc;

    #[test]
    fn test_empty_trie_hash() {
        let h = empty_trie_hash();
        assert_eq!(
            format!("{h:x}"),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn test_leaf_serialization_roundtrip() {
        let store = MemoryTrieStore::new();
        let path = TrieKeySlice::new(vec![1, 0, 1], 0, 3);
        let node = TrieNode::new_leaf(path.clone(), vec![0xAB, 0xCD]);

        let msg = node.to_message(&store);
        let decoded = TrieNode::from_message(&msg, &store);

        assert_eq!(decoded.shared_path, path);
        assert_eq!(decoded.value, Some(vec![0xAB, 0xCD]));
        assert!(decoded.left.is_empty());
        assert!(decoded.right.is_empty());
    }

    #[test]
    fn test_node_hash_deterministic() {
        let store = MemoryTrieStore::new();
        let node = TrieNode::new_leaf(TrieKeySlice::from_key(&[0x01]), vec![0xFF]);
        let h1 = node.compute_hash(&store);
        let h2 = node.compute_hash(&store);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_put_single_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);
        let root = root.put(&key, &[0xAA], &store);

        let val = root.get(&key, &store);
        assert_eq!(val, Some(vec![0xAA]));
    }

    #[test]
    fn test_put_two_diverging_keys() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]); // 00000000
        let k2 = TrieKeySlice::from_key(&[0x80]); // 10000000

        let root = root.put(&k1, b"val1", &store);
        let root = root.put(&k2, b"val2", &store);

        assert_eq!(root.get(&k1, &store), Some(b"val1".to_vec()));
        assert_eq!(root.get(&k2, &store), Some(b"val2".to_vec()));
    }

    #[test]
    fn test_put_overwrite() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x42]);

        let root = root.put(&key, b"old", &store);
        assert_eq!(root.get(&key, &store), Some(b"old".to_vec()));

        let root = root.put(&key, b"new", &store);
        assert_eq!(root.get(&key, &store), Some(b"new".to_vec()));
    }

    #[test]
    fn test_delete_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]);
        let k2 = TrieKeySlice::from_key(&[0x80]);

        let root = root.put(&k1, b"v1", &store);
        let root = root.put(&k2, b"v2", &store);
        let root = root.delete(&k1, &store);

        assert_eq!(root.get(&k1, &store), None);
        assert_eq!(root.get(&k2, &store), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete_last_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);

        let root = root.put(&key, b"val", &store);
        let root = root.delete(&key, &store);

        assert!(root.is_empty_trie());
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_save_and_reload() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x01]);
        let k2 = TrieKeySlice::from_key(&[0x02]);

        let root = root.put(&k1, b"a", store.as_ref());
        let mut root = root.put(&k2, b"b", store.as_ref());

        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        // Reload from store using only the hash
        let data = store.get(hash.as_slice()).expect("root should be saved");
        let reloaded = TrieNode::from_message(&data, store.as_ref());

        assert_eq!(reloaded.get(&k1, store.as_ref()), Some(b"a".to_vec()));
        assert_eq!(reloaded.get(&k2, store.as_ref()), Some(b"b".to_vec()));
        assert_eq!(reloaded.compute_hash(store.as_ref()), hash);
    }

    #[test]
    fn test_long_value() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);
        let long_val = vec![0xBB; 100]; // >32 bytes

        let mut root = root.put(&key, &long_val, store.as_ref());
        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).unwrap();
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        assert_eq!(reloaded.get(&key, store.as_ref()), Some(long_val));
    }

    #[test]
    fn test_many_keys() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();

        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            root = root.put(&key, &[i], &store);
        }

        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            assert_eq!(root.get(&key, &store), Some(vec![i]));
        }

        // Nonexistent key
        let key = TrieKeySlice::from_key(&[200]);
        assert_eq!(root.get(&key, &store), None);
    }

    /// A trie that branches, so that paths are more than a node or two deep.
    fn branching(store: &MemoryTrieStore) -> TrieNode {
        let mut root = TrieNode::empty();
        for i in 0u8..50 {
            root = root.put(&TrieKeySlice::from_key(&[i, 7]), &[i], store);
        }
        root
    }

    /// Each node is a child of the one after it, and the last is `root`.
    fn assert_chained(nodes: &[TrieNode], root: &TrieNode, store: &MemoryTrieStore) {
        assert_eq!(nodes.last().expect("a path").compute_hash(store), root.compute_hash(store));
        for pair in nodes.windows(2) {
            let (child, parent) = (&pair[0], &pair[1]);
            let message = child.to_message(store);
            let linked = [&parent.left, &parent.right]
                .iter()
                .any(|r| r.resolve(store).is_some_and(|c| c.to_message(store) == message));
            assert!(linked, "a node on the path is not a child of the one above it");
        }
    }

    /// A key the trie holds gets the path `nodes_on_path` gives it.
    #[test]
    fn nodes_toward_a_present_key_are_its_path() {
        let store = MemoryTrieStore::new();
        let root = branching(&store);
        let key = TrieKeySlice::from_key(&[21, 7]);

        let toward = root.try_nodes_toward(&key, &store).expect("a complete store");
        let on_path = root.nodes_on_path(&key, &store).expect("present");
        let messages = |nodes: &[TrieNode]| nodes.iter().map(|n| n.to_message(&store)).collect::<Vec<_>>();
        assert_eq!(messages(&toward), messages(&on_path));
    }

    /// A key the trie does not hold still gets a path, tied to the root, down
    /// to the node where it leaves the trie -- whichever way it leaves.
    #[test]
    fn nodes_toward_an_absent_key_end_where_it_leaves_the_trie() {
        let store = MemoryTrieStore::new();
        let root = branching(&store);
        let absent: [&[u8]; 4] = [
            &[200, 7],   // parts from every key early
            &[21, 8],    // shares the first byte of one, then parts
            &[21],       // ends inside the path to one
            &[21, 7, 1], // runs on past one
        ];
        for key in absent {
            let slice = TrieKeySlice::from_key(key);
            assert_eq!(root.try_get(&slice, &store), Ok(None), "{key:?} is in the trie");
            let nodes = root.try_nodes_toward(&slice, &store).expect("a complete store");
            assert_chained(&nodes, &root, &store);
        }

        // Running on past a key ends at that key's own node, which has no
        // child for the rest.
        let past = root
            .try_nodes_toward(&TrieKeySlice::from_key(&[21, 7, 1]), &store)
            .expect("a complete store");
        assert_eq!(past[0].value, Some(vec![21]));
    }

    /// A store that cannot follow the path proves nothing, and says so rather
    /// than answering that the key is absent.
    #[test]
    fn nodes_toward_through_an_incomplete_store_are_an_error() {
        let store = MemoryTrieStore::new();
        let mut root = branching(&store);
        root.save(&store, true);

        // The same root, read back against a store holding none of its
        // descendants.
        let empty = MemoryTrieStore::new();
        let detached = TrieNode::from_message(&root.to_message(&store), &empty);
        assert!(detached.try_nodes_toward(&TrieKeySlice::from_key(&[21, 8]), &empty).is_err());
    }

    #[test]
    fn test_hash_changes_on_put() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let k1 = TrieKeySlice::from_key(&[0x01]);

        let root1 = root.put(&k1, b"a", &store);
        let h1 = root1.compute_hash(&store);

        let root2 = root1.put(&k1, b"b", &store);
        let h2 = root2.compute_hash(&store);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_serialization_with_children() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]);
        let k2 = TrieKeySlice::from_key(&[0x80]);
        let k3 = TrieKeySlice::from_key(&[0x40]);

        let root = root.put(&k1, b"a", &store);
        let root = root.put(&k2, b"b", &store);
        let root = root.put(&k3, b"c", &store);

        let msg = root.to_message(&store);
        let decoded = TrieNode::from_message(&msg, &store);
        assert_eq!(decoded.compute_hash(&store), root.compute_hash(&store));
    }
}

#[cfg(test)]
mod thread_safety_assertions {
    /// Parallel sublist execution shares the parent root across worker
    /// threads, so this has to hold. It is asserted rather than assumed
    /// because adding an `Rc` anywhere in the node would break it silently.
    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<super::TrieNode>();
    const _: () = assert_send_sync::<super::NodeRef>();
}
