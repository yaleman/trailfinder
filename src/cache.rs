//! Command response caching system
//!
//! This module provides functionality to cache SSH command responses for offline development
//! and testing. Commands are cached with hostname as the primary key and command as the secondary key.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::TrailFinderError;

/// A cached command response with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// The command that was executed
    pub command: String,
    /// The stdout output from the command
    pub output: String,
    /// The stderr output from the command (if any)
    pub stderr: Option<String>,
    /// Exit code of the command (0 for success)
    pub exit_code: i32,
    /// When this response was cached
    pub timestamp: DateTime<Utc>,
}

impl CachedResponse {
    pub fn new(command: String, output: String, stderr: Option<String>, exit_code: i32) -> Self {
        Self {
            command,
            output,
            stderr,
            exit_code,
            timestamp: Utc::now(),
        }
    }

    /// Check if this cached response is considered fresh
    pub fn is_fresh(&self) -> bool {
        true
    }
}

/// Cache for command responses organized by hostname and command
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostCommandCache {
    /// Hostname this cache belongs to
    pub hostname: String,
    /// Map of command -> cached response
    pub responses: HashMap<String, CachedResponse>,
    /// When this cache file was last updated
    pub last_updated: DateTime<Utc>,
}

impl HostCommandCache {
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            responses: HashMap::new(),
            last_updated: Utc::now(),
        }
    }

    /// Add or update a cached response
    pub fn cache_response(&mut self, response: CachedResponse) {
        self.responses.insert(response.command.clone(), response);
        self.last_updated = Utc::now();
    }

    /// Get a cached response for a command
    pub fn get_response(&self, command: &str) -> Option<&CachedResponse> {
        self.responses.get(command)
    }

    /// Get a list of all cached commands
    pub fn get_cached_commands(&self) -> Vec<&String> {
        self.responses.keys().collect()
    }

    /// Remove old entries (older than 7 days)
    pub fn cleanup_old_entries(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::days(7);
        self.responses
            .retain(|_cmd, response| response.timestamp > cutoff);
        if !self.responses.is_empty() {
            self.last_updated = Utc::now();
        }
    }
}

/// Global command cache manager
pub struct CommandCache {
    /// Directory where cache files are stored
    cache_dir: PathBuf,
}

impl CommandCache {
    pub fn new_default() -> Result<Self, TrailFinderError> {
        let cache_dir = match dirs::cache_dir() {
            None => shellexpand::tilde("~/.cache/trailfinder")
                .parse()
                .map_err(|err| {
                    TrailFinderError::Io(std::io::Error::other(format!(
                        "Failed to determine user cache directory: {}",
                        err
                    )))
                })?,
            Some(val) => val.join("trailfinder"),
        };
        Self::new(cache_dir)
    }

    /// Create a new command cache manager
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self, TrailFinderError> {
        let cache_dir = cache_dir.as_ref().to_path_buf();

        // Create cache directory if it doesn't exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).map_err(|e| {
                TrailFinderError::Io(std::io::Error::other(format!(
                    "Failed to create cache directory: {}",
                    e
                )))
            })?;
        }

        Ok(Self { cache_dir })
    }

    /// Get the path to a cache file for a hostname
    fn cache_file_path(&self, hostname: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", hostname))
    }

    /// Load cache for a specific hostname
    pub fn load_host_cache(&self, hostname: &str) -> Result<HostCommandCache, TrailFinderError> {
        let cache_file = self.cache_file_path(hostname);

        if !cache_file.exists() {
            debug!(
                "No cache file found for hostname '{}', creating new cache",
                hostname
            );
            return Ok(HostCommandCache::new(hostname.to_string()));
        }

        let content = fs::read_to_string(&cache_file).map_err(|e| {
            TrailFinderError::Io(std::io::Error::other(format!(
                "Failed to read cache file for '{}': {}",
                hostname, e
            )))
        })?;

        let mut cache: HostCommandCache = serde_json::from_str(&content).map_err(|e| {
            TrailFinderError::Serde(format!(
                "Failed to parse cache file for '{}': {}",
                hostname, e
            ))
        })?;

        // Clean up old entries when loading
        cache.cleanup_old_entries();

        debug!(
            "Loaded cache for hostname '{}' with {} commands",
            hostname,
            cache.responses.len()
        );

        Ok(cache)
    }

    /// Save cache for a specific hostname
    pub fn save_host_cache(&self, cache: &HostCommandCache) -> Result<(), TrailFinderError> {
        let cache_file = self.cache_file_path(&cache.hostname);

        let content = serde_json::to_string_pretty(cache).map_err(|e| {
            TrailFinderError::Serde(format!(
                "Failed to serialize cache for '{}': {}",
                cache.hostname, e
            ))
        })?;

        if let Some(cache_parent) = cache_file.parent()
            && !cache_parent.exists()
        {
            fs::create_dir_all(cache_parent).map_err(|e| {
                TrailFinderError::Io(std::io::Error::other(format!(
                    "Failed to create cache directory for '{}': {}",
                    cache.hostname, e
                )))
            })?;
        }

        fs::write(&cache_file, content).map_err(|e| {
            TrailFinderError::Io(std::io::Error::other(format!(
                "Failed to write cache file for '{}': {}",
                cache.hostname, e
            )))
        })?;

        debug!(
            "Saved cache for hostname '{}' with {} commands",
            cache.hostname,
            cache.responses.len()
        );

        Ok(())
    }

    /// Cache a command response
    pub fn cache_command_response(
        &self,
        hostname: &str,
        command: &str,
        output: &str,
        stderr: Option<&str>,
        exit_code: i32,
    ) -> Result<(), TrailFinderError> {
        let mut cache = self.load_host_cache(hostname)?;

        let response = CachedResponse::new(
            command.to_string(),
            output.to_string(),
            stderr.map(|s| s.to_string()),
            exit_code,
        );

        cache.cache_response(response);
        self.save_host_cache(&cache)?;

        Ok(())
    }

    /// Get a cached command response
    pub fn get_cached_response(
        &self,
        hostname: &str,
        command: &str,
    ) -> Result<Option<CachedResponse>, TrailFinderError> {
        let cache = self.load_host_cache(hostname)?;
        Ok(cache.get_response(command).cloned())
    }

    /// Check if a command response exists in cache
    pub fn has_cached_response(&self, hostname: &str, command: &str) -> bool {
        match self.load_host_cache(hostname) {
            Ok(cache) => cache.get_response(command).is_some(),
            Err(_) => false,
        }
    }

    /// Get all hostnames that have cached data
    pub fn get_cached_hostnames(&self) -> Result<Vec<String>, TrailFinderError> {
        let mut hostnames = Vec::new();

        let entries = fs::read_dir(&self.cache_dir).map_err(|e| {
            TrailFinderError::Io(std::io::Error::other(format!(
                "Failed to read cache directory: {}",
                e
            )))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                TrailFinderError::Io(std::io::Error::other(format!(
                    "Failed to read cache directory entry: {}",
                    e
                )))
            })?;

            let path = entry.path();
            if path.is_file()
                && let Some(extension) = path.extension()
                && extension == "json"
                && let Some(hostname) = path.file_stem()
                && let Some(hostname_str) = hostname.to_str()
            {
                hostnames.push(hostname_str.to_string());
            }
        }

        Ok(hostnames)
    }

    /// Get statistics about the cache
    pub fn get_cache_stats(&self) -> Result<CacheStats, TrailFinderError> {
        let hostnames = self.get_cached_hostnames()?;
        let mut total_commands = 0;
        let mut total_size_bytes = 0;
        let mut oldest_entry = None;
        let mut newest_entry = None;

        for hostname in &hostnames {
            let cache = self.load_host_cache(hostname)?;
            total_commands += cache.responses.len();

            for response in cache.responses.values() {
                total_size_bytes += response.output.len() + response.command.len();
                if let Some(stderr) = &response.stderr {
                    total_size_bytes += stderr.len();
                }

                match (oldest_entry, newest_entry) {
                    (None, None) => {
                        oldest_entry = Some(response.timestamp);
                        newest_entry = Some(response.timestamp);
                    }
                    (Some(oldest), Some(newest)) => {
                        if response.timestamp < oldest {
                            oldest_entry = Some(response.timestamp);
                        }
                        if response.timestamp > newest {
                            newest_entry = Some(response.timestamp);
                        }
                    }
                    // Handle inconsistent state by resetting both entries
                    _ => {
                        oldest_entry = Some(response.timestamp);
                        newest_entry = Some(response.timestamp);
                    }
                }
            }
        }

        Ok(CacheStats {
            total_hostnames: hostnames.len(),
            total_commands,
            total_size_bytes,
            oldest_entry,
            newest_entry,
        })
    }

    /// Clean up old cache entries for all hosts
    pub fn cleanup_all_caches(&self) -> Result<usize, TrailFinderError> {
        let hostnames = self.get_cached_hostnames()?;
        let mut cleaned_count = 0;

        for hostname in hostnames {
            let mut cache = self.load_host_cache(&hostname)?;
            let original_count = cache.responses.len();
            cache.cleanup_old_entries();
            let new_count = cache.responses.len();

            if new_count < original_count {
                cleaned_count += original_count - new_count;
                self.save_host_cache(&cache)?;
            }
        }

        Ok(cleaned_count)
    }
}

/// Statistics about the command cache
#[derive(Debug)]
pub struct CacheStats {
    pub total_hostnames: usize,
    pub total_commands: usize,
    pub total_size_bytes: usize,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cache Statistics:")?;
        writeln!(f, "  Total hostnames: {}", self.total_hostnames)?;
        writeln!(f, "  Total commands: {}", self.total_commands)?;
        writeln!(f, "  Total size: {} bytes", self.total_size_bytes)?;

        if let Some(oldest) = self.oldest_entry {
            writeln!(
                f,
                "  Oldest entry: {}",
                oldest.format("%Y-%m-%d %H:%M:%S UTC")
            )?;
        }

        if let Some(newest) = self.newest_entry {
            writeln!(
                f,
                "  Newest entry: {}",
                newest.format("%Y-%m-%d %H:%M:%S UTC")
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_cache() -> (CommandCache, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache = CommandCache::new(temp_dir.path()).expect("Failed to create cache");
        (cache, temp_dir)
    }

    #[test]
    fn test_cached_response_creation() {
        let response = CachedResponse::new(
            "test command".to_string(),
            "output".to_string(),
            Some("stderr".to_string()),
            0,
        );

        assert_eq!(response.command, "test command");
        assert_eq!(response.output, "output");
        assert_eq!(response.stderr, Some("stderr".to_string()));
        assert_eq!(response.exit_code, 0);
        assert!(response.is_fresh());
    }

    #[test]
    fn test_host_command_cache_operations() {
        let mut cache = HostCommandCache::new("test-host".to_string());

        let response = CachedResponse::new(
            "test command".to_string(),
            "test output".to_string(),
            None,
            0,
        );

        cache.cache_response(response);

        assert_eq!(cache.responses.len(), 1);
        assert!(cache.get_response("test command").is_some());
        assert!(cache.get_response("nonexistent command").is_none());

        let commands = cache.get_cached_commands();
        assert_eq!(commands.len(), 1);
        assert!(commands.contains(&&"test command".to_string()));
    }

    #[test]
    fn test_command_cache_save_load() {
        let (cache_manager, _temp_dir) = create_test_cache();

        // Cache a response
        cache_manager
            .cache_command_response(
                "test-host",
                "test command",
                "test output",
                Some("test stderr"),
                0,
            )
            .expect("Failed to cache response");

        // Verify we can retrieve it
        let response = cache_manager
            .get_cached_response("test-host", "test command")
            .expect("Failed to get cached response")
            .expect("Response should exist");

        assert_eq!(response.command, "test command");
        assert_eq!(response.output, "test output");
        assert_eq!(response.stderr, Some("test stderr".to_string()));
        assert_eq!(response.exit_code, 0);
    }

    #[test]
    fn test_cache_persistence() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path().to_path_buf();

        // Create cache and add response
        {
            let cache_manager = CommandCache::new(&cache_dir).expect("Failed to create cache");
            cache_manager
                .cache_command_response("persistent-host", "persistent command", "output", None, 0)
                .expect("Failed to cache response");
        }

        // Create new cache manager and verify data persists
        {
            let cache_manager = CommandCache::new(&cache_dir).expect("Failed to create cache");
            let response = cache_manager
                .get_cached_response("persistent-host", "persistent command")
                .expect("Failed to get cached response")
                .expect("Response should exist");

            assert_eq!(response.command, "persistent command");
            assert_eq!(response.output, "output");
        }
    }

    #[test]
    fn test_has_cached_response() {
        let (cache_manager, _temp_dir) = create_test_cache();

        assert!(!cache_manager.has_cached_response("test-host", "test command"));

        cache_manager
            .cache_command_response("test-host", "test command", "output", None, 0)
            .expect("Failed to cache response");

        assert!(cache_manager.has_cached_response("test-host", "test command"));
        assert!(!cache_manager.has_cached_response("test-host", "other command"));
        assert!(!cache_manager.has_cached_response("other-host", "test command"));
    }

    #[test]
    fn test_get_cached_hostnames() {
        let (cache_manager, _temp_dir) = create_test_cache();

        // Initially no hostnames
        let hostnames = cache_manager
            .get_cached_hostnames()
            .expect("Failed to get hostnames");
        assert!(hostnames.is_empty());

        // Add cache for multiple hosts
        cache_manager
            .cache_command_response("host1", "command", "output", None, 0)
            .expect("Failed to cache response");
        cache_manager
            .cache_command_response("host2", "command", "output", None, 0)
            .expect("Failed to cache response");

        let hostnames = cache_manager
            .get_cached_hostnames()
            .expect("Failed to get hostnames");
        assert_eq!(hostnames.len(), 2);
        assert!(hostnames.contains(&"host1".to_string()));
        assert!(hostnames.contains(&"host2".to_string()));
    }

    #[test]
    fn test_cache_stats() {
        let (cache_manager, _temp_dir) = create_test_cache();

        // Add some cached responses
        cache_manager
            .cache_command_response("host1", "command1", "output1", None, 0)
            .expect("Failed to cache response");
        cache_manager
            .cache_command_response("host1", "command2", "output2", None, 0)
            .expect("Failed to cache response");
        cache_manager
            .cache_command_response("host2", "command3", "output3", Some("stderr"), 1)
            .expect("Failed to cache response");

        let stats = cache_manager
            .get_cache_stats()
            .expect("Failed to get stats");
        assert_eq!(stats.total_hostnames, 2);
        assert_eq!(stats.total_commands, 3);
        assert!(stats.total_size_bytes > 0);
        assert!(stats.oldest_entry.is_some());
        assert!(stats.newest_entry.is_some());
    }

    #[test]
    fn test_cleanup_old_entries() {
        let (cache_manager, _temp_dir) = create_test_cache();

        // Add some responses
        cache_manager
            .cache_command_response("test-host", "command1", "output1", None, 0)
            .expect("Failed to cache response");
        cache_manager
            .cache_command_response("test-host", "command2", "output2", None, 0)
            .expect("Failed to cache response");

        // Manually create an old entry by directly saving it without cleanup
        let mut cache = cache_manager
            .load_host_cache("test-host")
            .expect("Failed to load cache");
        let old_response = CachedResponse {
            command: "old command".to_string(),
            output: "old output".to_string(),
            stderr: None,
            exit_code: 0,
            timestamp: Utc::now() - chrono::Duration::days(10), // 10 days ago
        };
        cache.cache_response(old_response);

        // Save cache directly without the automatic cleanup that happens in save_host_cache
        let cache_file = cache_manager.cache_file_path("test-host");
        let content = serde_json::to_string_pretty(&cache).expect("Failed to serialize cache");
        std::fs::write(&cache_file, content).expect("Failed to write cache file");

        // Load cache again to get the count (this will trigger cleanup)
        let cache_before_cleanup = cache_manager
            .load_host_cache("test-host")
            .expect("Failed to load cache");
        // The cache should now have 2 commands (the old one was cleaned up on load)
        assert_eq!(cache_before_cleanup.responses.len(), 2);

        // Cleanup should not remove any additional entries (already cleaned on load)
        let cleaned_count = cache_manager
            .cleanup_all_caches()
            .expect("Failed to cleanup");
        assert_eq!(cleaned_count, 0);

        // After cleanup, should have 2 commands
        let cache = cache_manager
            .load_host_cache("test-host")
            .expect("Failed to load cache");
        assert_eq!(cache.responses.len(), 2);
        assert!(cache.get_response("command1").is_some());
        assert!(cache.get_response("command2").is_some());
        assert!(cache.get_response("old command").is_none());
    }
}
