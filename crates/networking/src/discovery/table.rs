use crate::discovery::message::DiscoveryNode;
use alloy_primitives::{keccak256, B256, B512};
use std::time::{Duration, Instant};

pub const BUCKET_SIZE: usize = 16;
pub const NUM_BUCKETS: usize = 256;

/// A node that hasn't been refreshed by our periodic discovery pings for this
/// long is treated as dead and may be evicted to make room for a fresh node in
/// a full bucket. rskj instead pings the least-recently-seen entry on the spot
/// (`NodeChallengeManager`) and evicts it only if it fails to pong; rustock's
/// discovery loop already pings every table node every 15s, so a stale
/// `last_seen` is the equivalent "lost challenge" signal. A bucket of
/// still-responsive nodes is left intact, matching rskj's bias toward keeping
/// known-good peers over unverified newcomers. See docs/wire-protocol.md.
const EVICTION_STALENESS: Duration = Duration::from_secs(90);

/// A table slot: the discovered node plus when we last heard from it (mirrors
/// rskj `BucketEntry`'s `lastSeenTime`). `last_seen` is liveness-only state and
/// is never serialized — it is not part of the wire/disk `DiscoveryNode`.
struct BucketEntry {
    node: DiscoveryNode,
    last_seen: Instant,
}

pub struct NodeTable {
    local_id: B512,
    /// `local_id`'s [`table_key`], which every distance is measured from.
    local_key: B256,
    buckets: Vec<Vec<BucketEntry>>,
}

impl NodeTable {
    pub fn new(local_id: B512) -> Self {
        Self {
            local_id,
            local_key: table_key(&local_id),
            // `BucketEntry` is intentionally not `Clone`, so build the buckets
            // with an iterator instead of the `vec![_; N]` (clone) macro.
            buckets: (0..NUM_BUCKETS).map(|_| Vec::new()).collect(),
        }
    }

    pub fn add_node(&mut self, node: DiscoveryNode) -> bool {
        if node.id == self.local_id {
            return false;
        }

        // rskj `NodeDistanceTable.getNodeBucket`: the distance less one, so
        // 0 to 255, and a node's ID is whatever a peer said it was.
        let bucket_idx = distance(&self.local_key, &table_key(&node.id)).saturating_sub(1);
        let now = Instant::now();

        let Some(bucket) = self.buckets.get_mut(bucket_idx) else {
            return false;
        };

        if let Some(pos) = bucket.iter().position(|e| e.node.id == node.id) {
            // Known node: refresh recency (move to end) and last-seen time.
            let mut entry = bucket.remove(pos);
            entry.last_seen = now;
            bucket.push(entry);
            true
        } else if bucket.len() < BUCKET_SIZE {
            bucket.push(BucketEntry { node, last_seen: now });
            true
        } else {
            // Bucket full. Entries are kept least-recently-seen first, so the
            // front is the eviction candidate (rskj `Bucket.getOldestEntry`).
            // Evict it only if it has gone stale — i.e. our periodic pings
            // stopped refreshing it, the equivalent of rskj's challenged node
            // failing to pong. Otherwise reject the newcomer.
            if bucket.first().is_some_and(|e| now.duration_since(e.last_seen) >= EVICTION_STALENESS) {
                bucket.remove(0);
                bucket.push(BucketEntry { node, last_seen: now });
                true
            } else {
                false
            }
        }
    }

    pub fn closest_nodes(&self, target: &B512, count: usize) -> Vec<DiscoveryNode> {
        let mut nodes: Vec<_> = self
            .buckets
            .iter()
            .flat_map(|b| b.iter().map(|e| e.node.clone()))
            .collect();
        // rskj `getClosestNodes`, sorted by `NodeDistanceComparator`.
        let target = table_key(target);
        nodes.sort_by_cached_key(|n| distance(&table_key(&n.id), &target));
        nodes.truncate(count);
        nodes
    }

    pub fn all_nodes(&self) -> Vec<DiscoveryNode> {
        self.buckets.iter().flat_map(|b| b.iter().map(|e| e.node.clone())).collect()
    }

    /// Total number of nodes across all buckets (without cloning).
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serializes the table to RLP bytes.
    pub fn encode(&self) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let nodes = self.all_nodes();
        let mut buf = Vec::new();
        nodes.encode(&mut buf);
        buf
    }

    /// Loads nodes from RLP-encoded bytes.
    pub fn decode_and_add(&mut self, data: &[u8]) -> anyhow::Result<()> {
        use alloy_rlp::Decodable;
        let mut ptr = data;
        let nodes = Vec::<DiscoveryNode>::decode(&mut ptr)
            .map_err(|e| anyhow::anyhow!("Failed to decode nodes: {:?}", e))?;

        for node in nodes {
            self.add_node(node);
        }
        Ok(())
    }

    /// Parses an enode URL and adds it to the table.
    /// Format: enode://<hex_id>@<ip>:<tcp_port>?discport=<udp_port>
    pub fn add_enode(&mut self, enode: &str) -> anyhow::Result<bool> {
        use alloy_primitives::hex::FromHex;

        if !enode.starts_with("enode://") {
            return Err(anyhow::anyhow!("Invalid enode prefix"));
        }
        
        let rest = &enode[8..];
        let parts: Vec<&str> = rest.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Missing @ in enode"));
        }
        
        let id_hex = parts[0];
        let addr_parts: Vec<&str> = parts[1].split(':').collect();
        if addr_parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid address format in enode"));
        }
        
        let host = addr_parts[0];
        let port_part = addr_parts[1];
        
        // Split port from query params
        let mut tcp_port_str = port_part;
        let mut udp_port = None;

        if let Some(pos) = port_part.find('?') {
            tcp_port_str = &port_part[..pos];
            let query = &port_part[pos+1..];
            for param in query.split('&') {
                if let Some(val) = param.strip_prefix("discport=") {
                    udp_port = Some(val.parse::<u16>()?);
                }
            }
        }

        let tcp_port: u16 = tcp_port_str.parse()?;
        let udp_port = udp_port.unwrap_or(tcp_port);

        // Resolve host to IP
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", host, tcp_port);
        let ip = addr_str.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve hostname: {}", host))?
            .ip();
        
        let id = B512::from_hex(id_hex)?;
        
        let node = DiscoveryNode {
            ip: alloy_primitives::Bytes::from(match ip {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            }),
            udp_port,
            tcp_port,
            id,
        };
        
        Ok(self.add_node(node))
    }

    /// Test helper: age every entry past the eviction threshold so the next
    /// `add_node` into a full bucket treats the oldest entry as dead.
    #[cfg(test)]
    fn force_all_stale(&mut self) {
        let old = Instant::now()
            .checked_sub(EVICTION_STALENESS + Duration::from_secs(1))
            .expect("test platform Instant should be old enough");
        for bucket in &mut self.buckets {
            for entry in bucket {
                entry.last_seen = old;
            }
        }
    }
}

/// The key rskj's Kademlia table orders a node by: `keccak256(keccak256(id))`
/// (`DistanceCalculator.calculateDistance`).
fn table_key(id: &B512) -> B256 {
    keccak256(keccak256(id))
}

/// rskj's distance between two [`table_key`]s: 256 less the leading zero bits
/// of their XOR, so 0 for the same node and 256 for keys whose first bits
/// differ (`DistanceCalculator.msbPosition`).
fn distance(a: &B256, b: &B256) -> usize {
    let mut leading_zeros = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        let byte = x ^ y;
        if byte != 0 {
            return 256 - leading_zeros - byte.leading_zeros() as usize;
        }
        leading_zeros += 8;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    fn node(id: B512) -> DiscoveryNode {
        DiscoveryNode {
            ip: Bytes::from(vec![10, 0, 0, 1]),
            udp_port: 5050,
            tcp_port: 5050,
            id,
        }
    }

    /// The `tag`-th ID, counting by its last two bytes, whose table key differs
    /// from the zero ID's in its first bit: all of them fall in bucket 255, so
    /// a test can fill one bucket.
    fn node_in_shared_bucket(tag: u8) -> DiscoveryNode {
        let local = table_key(&B512::ZERO);
        let id = (0..=u16::MAX)
            .map(|n| {
                let mut id = [0u8; 64];
                id[62..].copy_from_slice(&n.to_be_bytes());
                B512::from(id)
            })
            .filter(|id| distance(&local, &table_key(id)) == 256)
            .nth(usize::from(tag))
            .expect("half of all IDs fall in bucket 255");
        node(id)
    }

    #[test]
    fn full_bucket_keeps_fresh_nodes_and_rejects_newcomer() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        assert_eq!(table.len(), BUCKET_SIZE);

        // Bucket is full of freshly-seen nodes: a newcomer is rejected, and no
        // existing node is dropped (rskj keeps responsive peers).
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(!table.add_node(newcomer.clone()));
        assert_eq!(table.len(), BUCKET_SIZE);
        assert!(!table.all_nodes().iter().any(|n| n.id == newcomer.id));
    }

    #[test]
    fn full_bucket_evicts_stale_oldest_for_newcomer() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        let oldest = node_in_shared_bucket(0);

        // Once every entry is stale (our pings stopped refreshing them), the
        // least-recently-seen node is evicted to admit the newcomer.
        table.force_all_stale();
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(table.add_node(newcomer.clone()));
        assert_eq!(table.len(), BUCKET_SIZE);
        assert!(table.all_nodes().iter().any(|n| n.id == newcomer.id));
        assert!(!table.all_nodes().iter().any(|n| n.id == oldest.id));
    }

    #[test]
    fn re_adding_refreshes_recency() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        // Mark all stale, then touch node 0 so it becomes most-recently-seen.
        table.force_all_stale();
        assert!(table.add_node(node_in_shared_bucket(0)));

        // The newcomer now evicts the *new* oldest (node 1), not the refreshed 0.
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(table.add_node(newcomer));
        assert!(table.all_nodes().iter().any(|n| n.id == node_in_shared_bucket(0).id));
        assert!(!table.all_nodes().iter().any(|n| n.id == node_in_shared_bucket(1).id));
    }

    /// rskj's `DistanceCalculatorTest` (a node is at distance 0 from itself, and
    /// distance is symmetric), and the edges of `msbPosition`.
    #[test]
    fn distance_is_rskjs() {
        let (a, b) = (B512::from([0x82; 64]), B512::with_last_byte(1));
        assert_eq!(distance(&table_key(&a), &table_key(&a)), 0);
        assert_eq!(
            distance(&table_key(&a), &table_key(&b)),
            distance(&table_key(&b), &table_key(&a))
        );
        assert_eq!(distance(&B256::ZERO, &B256::with_last_byte(1)), 1);
        assert_eq!(distance(&B256::ZERO, &B256::with_last_byte(0x80)), 8);
        let mut first = [0u8; 32];
        first[0] = 0x01;
        assert_eq!(distance(&B256::ZERO, &B256::from(first)), 249);
        first[0] = 0x80;
        assert_eq!(distance(&B256::ZERO, &B256::from(first)), 256);
    }

    /// A peer names nodes by any 64 bytes it likes, among them IDs that match
    /// ours in all but one bit, and each has a bucket.
    #[test]
    fn every_id_a_peer_can_name_has_a_bucket() {
        let local = B512::from([0x5A; 64]);
        let mut table = NodeTable::new(local);
        for byte in 0..64 {
            for bit in 0..8 {
                let mut id = local.0;
                id[byte] ^= 1 << bit;
                table.add_node(node(B512::from(id)));
            }
        }
        assert!(!table.is_empty());
    }

    /// rskj's `getClosestNodes`: the nodes nearest the target by rskj's distance.
    #[test]
    fn closest_nodes_are_nearest_by_rskjs_distance() {
        let mut table = NodeTable::new(B512::ZERO);
        for tag in 1..=40 {
            table.add_node(node(B512::with_last_byte(tag)));
        }
        let target = table_key(&B512::with_last_byte(77));
        let distance_to = |n: &DiscoveryNode| distance(&table_key(&n.id), &target);
        let closest = table.closest_nodes(&B512::with_last_byte(77), 10);
        assert_eq!(closest.len(), 10);
        assert!(closest
            .windows(2)
            .all(|w| distance_to(&w[0]) <= distance_to(&w[1])));
        let farthest = distance_to(&closest[9]);
        assert!(table
            .all_nodes()
            .iter()
            .all(|n| closest.iter().any(|c| c.id == n.id) || distance_to(n) >= farthest));
    }
}
