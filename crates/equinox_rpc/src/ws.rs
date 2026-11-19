#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionTopic {
    NewHeads,
    PendingTransactions,
    AddressActivity(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionEvent {
    pub subscription_id: u64,
    pub topic: SubscriptionTopic,
    pub payload: serde_json::Value,
}

struct Subscriber {
    topic: SubscriptionTopic,
    queue: VecDeque<SubscriptionEvent>,
}

/// Bounded-queue real-time WebSocket subscription hub preventing slow-client RAM exhaustion.
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
        self.next_id = self.next_id.saturating_add(1);
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

    /// Publishes an event to matching subscribers; drops oldest unread event if a client lags.
    pub fn publish(&mut self, topic: &SubscriptionTopic, payload: serde_json::Value) -> usize {
        let mut delivered = 0usize;
        for (&id, sub) in self.subs.iter_mut() {
            if &sub.topic == topic {
                if sub.queue.len() >= self.max_queue_per_sub {
                    sub.queue.pop_front();
                }
                sub.queue.push_back(SubscriptionEvent {
                    subscription_id: id,
                    topic: topic.clone(),
                    payload: payload.clone(),
                });
                delivered += 1;
            }
        }
        delivered
    }

    pub fn pop_event(&mut self, id: u64) -> Option<SubscriptionEvent> {
        self.subs.get_mut(&id)?.queue.pop_front()
    }
}
