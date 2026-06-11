//! Proxy rotation strategies.

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

/// A pool of proxy configurations with rotation.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    /// Available proxies.
    pub proxies: Vec<ProxyConfig>,
    /// How to pick the next proxy.
    pub strategy: RotationStrategy,
    index: usize,
}

impl ProxyPool {
    /// Create a new pool with the given proxies and strategy.
    pub fn new(proxies: Vec<ProxyConfig>, strategy: RotationStrategy) -> Self {
        Self {
            proxies,
            strategy,
            index: 0,
        }
    }

    /// Get the next proxy according to the rotation strategy.
    ///
    /// # Panics
    /// Panics if the pool is empty.
    pub fn next(&mut self) -> &ProxyConfig {
        match self.strategy {
            RotationStrategy::RoundRobin => {
                let proxy = &self.proxies[self.index % self.proxies.len()];
                self.index = self.index.wrapping_add(1);
                proxy
            }
            RotationStrategy::Random => {
                // Simple deterministic "random" without pulling in rand crate
                self.index = (self.index.wrapping_mul(6364136223846793005).wrapping_add(1))
                    % self.proxies.len();
                &self.proxies[self.index]
            }
        }
    }
}
