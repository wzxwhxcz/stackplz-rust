use std::collections::HashSet;

/// Advanced filter for UID/PID blacklist
#[derive(Debug, Clone)]
pub struct AdvancedFilter {
    uid_blacklist: HashSet<u32>,
    pid_blacklist: HashSet<u32>,
    sdk_int: u32,
}

impl AdvancedFilter {
    pub fn new() -> Self {
        Self {
            uid_blacklist: HashSet::new(),
            pid_blacklist: HashSet::new(),
            sdk_int: 0,
        }
    }

    /// Parse comma-separated list into HashSet
    fn parse_list(s: &str) -> HashSet<u32> {
        s.split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect()
    }

    /// Set UID blacklist from comma-separated string
    pub fn set_uid_blacklist(&mut self, uids: &str) {
        self.uid_blacklist = Self::parse_list(uids);
    }

    /// Set PID blacklist from comma-separated string
    pub fn set_pid_blacklist(&mut self, pids: &str) {
        self.pid_blacklist = Self::parse_list(pids);
    }

    /// Set SDK version filter
    pub fn set_sdk_int(&mut self, sdk: u32) {
        self.sdk_int = sdk;
    }

    /// Check if UID is blacklisted
    pub fn is_uid_blocked(&self, uid: u32) -> bool {
        self.uid_blacklist.contains(&uid)
    }

    /// Check if PID is blacklisted
    pub fn is_pid_blocked(&self, pid: u32) -> bool {
        self.pid_blacklist.contains(&pid)
    }

    /// Check if event should be filtered
    pub fn should_filter(&self, uid: u32, pid: u32) -> bool {
        self.is_uid_blocked(uid) || self.is_pid_blocked(pid)
    }

    /// Get SDK version requirement
    pub fn get_sdk_int(&self) -> u32 {
        self.sdk_int
    }
}

impl Default for AdvancedFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_list() {
        let set = AdvancedFilter::parse_list("1,2,3");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
    }

    #[test]
    fn test_parse_list_with_spaces() {
        let set = AdvancedFilter::parse_list("1, 2 , 3");
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_parse_list_empty() {
        let set = AdvancedFilter::parse_list("");
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_parse_list_invalid() {
        let set = AdvancedFilter::parse_list("1,abc,3");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&1));
        assert!(set.contains(&3));
    }

    #[test]
    fn test_uid_blacklist() {
        let mut filter = AdvancedFilter::new();
        filter.set_uid_blacklist("1000,2000,3000");

        assert!(filter.is_uid_blocked(1000));
        assert!(filter.is_uid_blocked(2000));
        assert!(filter.is_uid_blocked(3000));
        assert!(!filter.is_uid_blocked(4000));
    }

    #[test]
    fn test_pid_blacklist() {
        let mut filter = AdvancedFilter::new();
        filter.set_pid_blacklist("100,200,300");

        assert!(filter.is_pid_blocked(100));
        assert!(filter.is_pid_blocked(200));
        assert!(filter.is_pid_blocked(300));
        assert!(!filter.is_pid_blocked(400));
    }

    #[test]
    fn test_should_filter() {
        let mut filter = AdvancedFilter::new();
        filter.set_uid_blacklist("1000");
        filter.set_pid_blacklist("100");

        assert!(filter.should_filter(1000, 200));
        assert!(filter.should_filter(2000, 100));
        assert!(filter.should_filter(1000, 100));
        assert!(!filter.should_filter(2000, 200));
    }

    #[test]
    fn test_sdk_int() {
        let mut filter = AdvancedFilter::new();
        assert_eq!(filter.get_sdk_int(), 0);

        filter.set_sdk_int(28);
        assert_eq!(filter.get_sdk_int(), 28);
    }
}
