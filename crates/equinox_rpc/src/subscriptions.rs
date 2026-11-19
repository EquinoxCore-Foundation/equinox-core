#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionTopic {
    NewHeads,
    NewPendingTransactions,
    AddressActivity(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionEvent {
    pub subscription_id: u64,
    pub topic: SubscriptionTopic,
    pub payload: Value,
}

struct Subscriber {
    topic: SubscriptionTopic,
    queue: VecDeque<SubscriptionEvent>,
}

/// Memory-bounded WebSocket Pub/Sub event broker for live wallets, POS terminals, and explorers.
pub struct SubscriptionHub {
    next_id: u64,
    max_subscribers: usize,
    max_queue_per_sub: usize,
    subs: HashMap<u64, Subscriber>,
}

impl SubscriptionHub {
    pub fn new(max_subscribers: usize, max_queue_per_sub: usize) -> Self {
        Self {
            next_id: 1,
            max_subscribers,
            max_queue_per_sub: max_queue_per_sub.max(1),
            subs: HashMap::new(),
        }
    }

    pub fn subscribe(&mut self, topic: SubscriptionTopic) -> Option<u64> {
        if self.subs.len() >= self.max_subscribers {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.subs.insert(
            id,
            Subscriber {
                topic,
                queue: VecDeque::with_capacity(self.max_queue_per_sub.min(64)),
            },
        );
        Some(id)
    }

    pub fn unsubscribe(&mut self, id: u64) -> bool {
        self.subs.remove(&id).is_some()
    }

    pub fn publish(&mut self, topic: &SubscriptionTopic, payload: Value) -> usize {
        let mut delivered = 0;
        for (&sub_id, sub) in &mut self.subs {
            if &sub.topic == topic {
                if sub.queue.len() >= self.max_queue_per_sub {
                    sub.queue.pop_front(); // Drop oldest event to prevent RAM exhaustion
                }
                sub.queue.push_back(SubscriptionEvent {
                    subscription_id: sub_id,
                    topic: topic.clone(),
                    payload: payload.clone(),
                });
                delivered += 1;
            }
        }
        delivered
    }

    pub fn drain_events(&mut self, id: u64) -> Vec<SubscriptionEvent> {
        self.subs
            .get_mut(&id)
            .map(|s| s.queue.drain(..).collect())
            .unwrap_or_default()
    }

    pub fn subscriber_count(&self) -> usize {
        self.subs.len()
    }
}
