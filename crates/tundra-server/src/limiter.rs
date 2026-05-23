use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::Instant;

pub struct ConnectionLimiter {
    max_global: usize,
    max_per_ip: usize,
    per_ip: Arc<tokio::sync::Mutex<HashMap<IpAddr, PerIpEntry>>>,
    global_count: AtomicUsize,
}

struct PerIpEntry {
    count: usize,
    last_seen: Instant,
}

impl ConnectionLimiter {
    pub fn new(max_connections: usize, max_per_ip: usize) -> Self {
        Self {
            max_global: max_connections,
            max_per_ip,
            per_ip: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            global_count: AtomicUsize::new(0),
        }
    }

    pub async fn acquire(&self, ip: IpAddr) -> Result<(), ()> {
        let current = self.global_count.load(Ordering::Relaxed);
        if current >= self.max_global {
            return Err(());
        }

        let mut per_ip = self.per_ip.lock().await;
        let now = Instant::now();
        let entry = per_ip.entry(ip).or_insert(PerIpEntry { count: 0, last_seen: now });

        if now.duration_since(entry.last_seen) > Duration::from_secs(300) {
            entry.count = 0;
        }

        if entry.count >= self.max_per_ip {
            return Err(());
        }

        entry.count += 1;
        entry.last_seen = now;
        self.global_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn release(&self, ip: IpAddr) {
        self.global_count.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut per_ip) = self.per_ip.try_lock() {
            if let Some(entry) = per_ip.get_mut(&ip) {
                entry.count = entry.count.saturating_sub(1);
            }
        }
    }
}
