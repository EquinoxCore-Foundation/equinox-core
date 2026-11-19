#![forbid(unsafe_code)]

pub mod errors;
pub mod metrics;
pub mod ratelimit;
pub mod router;
pub mod subscriptions;

#[cfg(test)]
mod tests {
    use crate::errors::{ERR_BATCH_LIMIT, ERR_RATE_LIMITED, ERR_UNAUTHORIZED};
    use crate::router::{JsonRpcResponse, RpcRouter};
    use crate::subscriptions::SubscriptionTopic;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn test_explorer_metrics_and_balance_rpc() {
        let mut router = RpcRouter::new(Some("SecretAdminToken#9333".to_string()));
        router.metrics.block_height = 1482;
        router.metrics.total_txns = 9450;
        let addr = "E111111111111111111111111111111111";
        router.balances.insert(addr.to_string(), 50_000_000_000);

        let stats_raw = router.handle_raw(
            test_ip(),
            1000,
            None,
            r#"{"jsonrpc":"2.0","method":"eqx_getExplorerStats","params":[],"id":1}"#,
        );
        let stats_resp: JsonRpcResponse = serde_json::from_str(&stats_raw).unwrap();
        assert_eq!(stats_resp.result.unwrap()["block_height"], 1482);

        let bal_raw = router.handle_raw(
            test_ip(),
            1001,
            None,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"eqx_getBalance","params":["{}"],"id":2}}"#,
                addr
            ),
        );
        let bal_resp: JsonRpcResponse = serde_json::from_str(&bal_raw).unwrap();
        assert_eq!(bal_resp.result.unwrap()["balance_atomic"], "50000000000");
    }

    #[test]
    fn test_admin_constant_time_auth_enforcement() {
        let mut router = RpcRouter::new(Some("SuperSecretMainnetKey".to_string()));
        let req = r#"{"jsonrpc":"2.0","method":"admin_setMining","params":[true],"id":7}"#;

        // Unauthenticated call rejected
        let r1: JsonRpcResponse =
            serde_json::from_str(&router.handle_raw(test_ip(), 1000, None, req)).unwrap();
        assert_eq!(r1.error.unwrap().code, ERR_UNAUTHORIZED);
        assert!(!router.mining_enabled);

        // Wrong token rejected
        let r2: JsonRpcResponse =
            serde_json::from_str(&router.handle_raw(test_ip(), 1001, Some("WrongKey"), req))
                .unwrap();
        assert_eq!(r2.error.unwrap().code, ERR_UNAUTHORIZED);

        // Valid token succeeds
        let r3: JsonRpcResponse = serde_json::from_str(&router.handle_raw(
            test_ip(),
            1002,
            Some("SuperSecretMainnetKey"),
            req,
        ))
        .unwrap();
        assert_eq!(r3.result.unwrap()["mining_enabled"], true);
        assert!(router.mining_enabled);
    }

    #[test]
    fn test_batch_amplification_and_rate_limit_protection() {
        let mut router = RpcRouter::new(None);

        // 25 calls in one batch exceeds MAX_RPC_BATCH_SIZE (20)
        let big_batch: Vec<_> = (0..25)
            .map(|i| json!({"jsonrpc":"2.0","method":"eqx_chainId","params":[],"id":i}))
            .collect();
        let batch_raw = router.handle_raw(
            test_ip(),
            1000,
            None,
            &serde_json::to_string(&big_batch).unwrap(),
        );
        let batch_resp: JsonRpcResponse = serde_json::from_str(&batch_raw).unwrap();
        assert_eq!(batch_resp.error.unwrap().code, ERR_BATCH_LIMIT);

        // Exhaust 60-token burst bucket -> 61st immediate call rate-limited
        let single = r#"{"jsonrpc":"2.0","method":"eqx_chainId","params":[],"id":1}"#;
        let mut hit_limit = false;
        for _ in 0..65 {
            let res: JsonRpcResponse =
                serde_json::from_str(&router.handle_raw(test_ip(), 2000, None, single)).unwrap();
            if let Some(err) = res.error {
                if err.code == ERR_RATE_LIMITED {
                    hit_limit = true;
                    break;
                }
            }
        }
        assert!(hit_limit);
    }

    #[test]
    fn test_websocket_subscription_hub_delivery_and_oom_cap() {
        let mut router = RpcRouter::new(None);
        let sub_raw = router.handle_raw(
            test_ip(),
            1000,
            None,
            r#"{"jsonrpc":"2.0","method":"eqx_subscribe","params":["newHeads"],"id":9}"#,
        );
        let sub_resp: JsonRpcResponse = serde_json::from_str(&sub_raw).unwrap();
        let sub_id = sub_resp.result.unwrap()["subscription_id"].as_u64().unwrap();

        // Publish 100 events into a queue capped at 64 -> must keep newest 64 without OOM
        for h in 1..=100u64 {
            router
                .subscriptions
                .publish(&SubscriptionTopic::NewHeads, json!({ "height": h }));
        }
        let events = router.subscriptions.drain_events(sub_id);
        assert_eq!(events.len(), 64);
        assert_eq!(events.first().unwrap().payload["height"], 37);
        assert_eq!(events.last().unwrap().payload["height"], 100);
    }
}
