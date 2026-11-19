#![forbid(unsafe_code)]

pub mod banlist;
pub mod discovery;
pub mod nat;
pub mod protocol;
pub mod ratelimit;
pub mod transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    NoiseFailure,
    FrameTooLarge,
    InvalidCiphertext,
    RateLimitExceeded,
    NonRoutableAddress,
    PeerTableFull,
    SubnetCapExceeded,
    SlotLimitReached,
    MalformedWireFrame,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banlist::{BanManager, Misbehavior};
    use crate::discovery::PeerTable;
    use crate::nat::{ConnectionSlotManager, ExternalAddressConsensus};
    use crate::protocol::{WireMessage, CHAIN_ID_MAINNET, PROTOCOL_VERSION};
    use crate::ratelimit::PeerRateLimiter;
    use crate::transport::{NodeStaticKey, NoiseHandshake, MAINNET_PROLOGUE};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_noise_xx_mutual_auth_e2ee_and_tamper_rejection() {
        let alice_key = NodeStaticKey::generate().unwrap();
        let bob_key = NodeStaticKey::generate().unwrap();

        let mut alice_hs = NoiseHandshake::new_initiator(&alice_key, MAINNET_PROLOGUE).unwrap();
        let mut bob_hs = NoiseHandshake::new_responder(&bob_key, MAINNET_PROLOGUE).unwrap();

        // 3-message Noise XX handshake (-> e, <- e ee s es, -> s se)
        let m1 = alice_hs.write_step(b"").unwrap();
        bob_hs.read_step(&m1).unwrap();

        let m2 = bob_hs.write_step(b"bob_hello").unwrap();
        assert_eq!(alice_hs.read_step(&m2).unwrap(), b"bob_hello");

        let m3 = alice_hs.write_step(b"alice_hello").unwrap();
        assert_eq!(bob_hs.read_step(&m3).unwrap(), b"alice_hello");

        assert!(alice_hs.is_finished() && bob_hs.is_finished());

        let mut alice_ch = alice_hs.into_transport().unwrap();
        let mut bob_ch = bob_hs.into_transport().unwrap();

        // Verify cryptographic mutual static key authentication
        assert_eq!(alice_ch.remote_public_key(), Some(bob_key.public_bytes()));
        assert_eq!(bob_ch.remote_public_key(), Some(alice_key.public_bytes()));

        // Encrypt & decrypt a real wire message over Noise transport
        let raw_msg = WireMessage::InvBlock([0xABu8; 32]).encode();
        let mut encrypted = alice_ch.encrypt_frame(&raw_msg).unwrap();
        assert_ne!(encrypted, raw_msg);
        let decrypted = bob_ch.decrypt_frame(&encrypted).unwrap();
        assert_eq!(WireMessage::decode(&decrypted).unwrap(), WireMessage::InvBlock([0xABu8; 32]));

        // Single bit flip in ciphertext must fail ChaCha20-Poly1305 AEAD verification
        encrypted[5] ^= 0x80;
        assert_eq!(
            bob_ch.decrypt_frame(&encrypted),
            Err(NetworkError::InvalidCiphertext)
        );
    }

    #[test]
    fn test_noise_rejects_mismatched_chain_prologue() {
        let a = NodeStaticKey::generate().unwrap();
        let b = NodeStaticKey::generate().unwrap();
        let mut hs_a = NoiseHandshake::new_initiator(&a, MAINNET_PROLOGUE).unwrap();
        let mut hs_b = NoiseHandshake::new_responder(&b, b"WRONG_CHAIN_PROLOGUE").unwrap();

        let m1 = hs_a.write_step(b"").unwrap();
        hs_b.read_step(&m1).unwrap();
        let m2 = hs_b.write_step(b"").unwrap();
        // Handshake cryptographically fails on mismatched prologue
        assert_eq!(hs_a.read_step(&m2), Err(NetworkError::NoiseFailure));
    }

    #[test]
    fn test_anti_dos_token_bucket_rate_limiter() {
        let mut rl = PeerRateLimiter::custom(3, 2, 1_000, 500, 10_000);
        assert!(rl.check_and_consume(200, 10_000).is_ok());
        assert!(rl.check_and_consume(200, 10_000).is_ok());
        assert!(rl.check_and_consume(200, 10_000).is_ok());
        // 4th immediate burst message must be blocked
        assert_eq!(
            rl.check_and_consume(200, 10_000),
            Err(NetworkError::RateLimitExceeded)
        );
        // After 1 second refill, traffic is allowed again
        assert!(rl.check_and_consume(200, 11_000).is_ok());
    }

    #[test]
    fn test_banlist_scoring_expiry_and_seed_whitelist() {
        let mut bans = BanManager::new(100, 3_600);
        let attacker = IpAddr::V4(Ipv4Addr::new(45, 12, 88, 9));
        let seed = IpAddr::V4(Ipv4Addr::new(104, 21, 5, 1));
        bans.whitelist_ip(seed);

        assert!(!bans.record_offense(attacker, Misbehavior::InvalidSignature, 1_000));
        assert_eq!(bans.score_of(attacker), 50);
        assert!(!bans.is_banned(attacker, 1_000));

        // Second invalid signature hits 100 -> banned for 3600s
        assert!(bans.record_offense(attacker, Misbehavior::InvalidSignature, 1_000));
        assert!(bans.is_banned(attacker, 2_000));
        assert!(!bans.is_banned(attacker, 4_600)); // Expired cleanly

        // Whitelisted DNS seed can never be banned
        assert!(!bans.record_offense(seed, Misbehavior::InvalidBlockPoW, 1_000));
        assert!(!bans.is_banned(seed, 1_000));
    }

    #[test]
    fn test_eclipse_resistant_subnet_cap_and_pex() {
        let mut table = PeerTable::mainnet_default();

        // Private LAN IPs rejected on strict mainnet peer table
        let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 19333);
        assert_eq!(table.add_peer(lan, 100, false), Err(NetworkError::NonRoutableAddress));

        // Allow up to 2 peers in same /16 (8.8.x.x), reject 3rd to block Eclipse attack
        let p1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 1, 1)), 19333);
        let p2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 2, 2)), 19333);
        let p3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 3, 3)), 19333);
        assert_eq!(table.add_peer(p1, 100, false), Ok(true));
        assert_eq!(table.add_peer(p2, 101, false), Ok(true));
        assert_eq!(table.add_peer(p3, 102, false), Err(NetworkError::SubnetCapExceeded));

        let pex = table.select_pex_batch(p1.ip(), 10);
        assert_eq!(pex, vec![p2]);
    }

    #[test]
    fn test_nat_external_ip_consensus_and_slot_limits() {
        let mut nat = ExternalAddressConsensus::new(3);
        let my_real_ip = IpAddr::V4(Ipv4Addr::new(103, 44, 12, 8));

        // 2 reports from same /16 subnet only count as 1 vote
        nat.record_peer_report(IpAddr::V4(Ipv4Addr::new(20, 10, 1, 1)), my_real_ip);
        nat.record_peer_report(IpAddr::V4(Ipv4Addr::new(20, 10, 2, 2)), my_real_ip);
        assert_eq!(nat.resolved_external_ip(), None);

        // 2 more distinct /16 subnets confirm -> consensus reached
        nat.record_peer_report(IpAddr::V4(Ipv4Addr::new(34, 55, 1, 1)), my_real_ip);
        nat.record_peer_report(IpAddr::V4(Ipv4Addr::new(52, 77, 1, 1)), my_real_ip);
        assert_eq!(nat.resolved_external_ip(), Some(my_real_ip));

        // Slot manager enforces strict outbound cap
        let mut slots = ConnectionSlotManager::new(1, 2);
        let s1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 19333);
        let s2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 19333);
        assert!(slots.add_outbound(s1, true).is_ok());
        assert_eq!(slots.add_outbound(s2, false), Err(NetworkError::SlotLimitReached));
        assert_eq!(slots.anchor_count(), 1);
    }

    #[test]
    fn test_wire_protocol_version_roundtrip() {
        let msg = WireMessage::Version {
            protocol_version: PROTOCOL_VERSION,
            chain_id: CHAIN_ID_MAINNET,
            best_height: 15_420,
            nonce: 0xDEAD_BEEF_CAFE_BABE,
        };
        let encoded = msg.encode();
        assert_eq!(WireMessage::decode(&encoded).unwrap(), msg);
        assert_eq!(
            WireMessage::decode(b"BAD!12345"),
            Err(NetworkError::MalformedWireFrame)
        );
    }
}
