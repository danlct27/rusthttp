//! Proxy rotation strategies.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ProxyError;
use crate::tunnel::ProxyConfig;

/// Strategy for selecting the next proxy from the pool.
#[derive(Debug, Clone, Copy, Default)]
pub enum RotationStrategy {
    /// Cycle through proxies in order.
    #[default]
    RoundRobin,
    /// Select a random proxy each time.
    Random,
}

/// Failure state for a proxy.
#[derive(Debug, Clone)]
struct ProxyState {
    /// Number of consecutive failures.
    failures: u32,
    /// Whether temporarily blacklisted.
    blacklisted: bool,
}

/// A pool of proxy configurations with rotation.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    /// Available proxies.
    pub proxies: Vec<ProxyConfig>,
    /// Per-proxy failure tracking.
    states: Vec<ProxyState>,
    /// How to pick the next proxy.
    pub strategy: RotationStrategy,
    index: usize,
    /// Max consecutive failures before blacklisting.
    max_failures: u32,
}

impl ProxyPool {
    /// Create a new pool with the given proxies and strategy.
    pub fn new(proxies: Vec<ProxyConfig>, strategy: RotationStrategy) -> Self {
        let len = proxies.len();
        // Seed index from current time for randomness
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as usize)
            .unwrap_or(0);
        Self {
            proxies,
            states: vec![ProxyState { failures: 0, blacklisted: false }; len],
            strategy,
            index: seed % len.max(1),
            max_failures: 3,
        }
    }

    /// Get the next healthy proxy according to the rotation strategy.
    /// Returns error if no healthy proxies available.
    pub fn select(&mut self) -> Result<&ProxyConfig, ProxyError> {
        if self.proxies.is_empty() {
            return Err(ProxyError::PoolExhausted);
        }

        let len = self.proxies.len();
        // Try up to `len` proxies to find a non-blacklisted one
        for _ in 0..len {
            let idx = match self.strategy {
                RotationStrategy::RoundRobin => {
                    let i = self.index % len;
                    self.index = self.index.wrapping_add(1);
                    i
                }
                RotationStrategy::Random => {
                    self.index = self.index.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    self.index % len
                }
            };
            if !self.states[idx].blacklisted {
                return Ok(&self.proxies[idx]);
            }
        }

        // All blacklisted — propagate error, don't silently retry
        Err(ProxyError::PoolExhausted)
    }

    /// Reset all blacklisted proxies (caller decides when to retry).
    pub fn reset_all(&mut self) {
        for state in &mut self.states {
            state.blacklisted = false;
            state.failures = 0;
        }
    }

    /// Report a failure for the proxy at the given URL.
    pub fn report_failure(&mut self, url: &str) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == url) {
            self.states[idx].failures += 1;
            if self.states[idx].failures >= self.max_failures {
                self.states[idx].blacklisted = true;
            }
        }
    }

    /// Report success for the proxy at the given URL (resets failure count).
    pub fn report_success(&mut self, url: &str) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == url) {
            self.states[idx].failures = 0;
            self.states[idx].blacklisted = false;
        }
    }
}
