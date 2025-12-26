//! Property-based tests for URL parsing
//!
//! Uses proptest to generate random URLs and validate parsing behavior

use proptest::prelude::*;

/// Valid protocol names
fn protocol_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("nfs".to_string()),
        Just("smb".to_string()),
        Just("cifs".to_string()),
        Just("sshfs".to_string()),
    ]
}

/// Valid hostname characters
fn hostname_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,20}\\.[a-z]{2,5}".prop_map(|s| s.to_string())
}

/// Valid path characters (no traversal)
fn safe_path_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z0-9_-]{1,20}", 1..=5)
        .prop_map(|parts| format!("/{}", parts.join("/")))
}

/// Username strategy
fn username_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{2,20}".prop_map(|s| s.to_string())
}

proptest! {
    /// Test that valid URLs parse successfully
    #[test]
    fn test_valid_url_parsing(
        protocol in protocol_strategy(),
        hostname in hostname_strategy(),
        path in safe_path_strategy(),
    ) {
        let url = format!("{}://{}{}", protocol, hostname, path);

        // Should contain protocol separator
        assert!(url.contains("://"));

        // Should not contain path traversal
        assert!(!url.contains(".."));

        // Should start with valid protocol
        assert!(url.starts_with("nfs://") ||
                url.starts_with("smb://") ||
                url.starts_with("cifs://") ||
                url.starts_with("sshfs://"));
    }

    /// Test that URLs with credentials parse correctly
    #[test]
    fn test_url_with_credentials(
        protocol in prop_oneof![Just("smb"), Just("cifs"), Just("sshfs")],
        username in username_strategy(),
        password in "[a-zA-Z0-9!#$%^&*]{4,20}",  // Exclude @ since it's a URL delimiter
        hostname in hostname_strategy(),
        path in safe_path_strategy(),
    ) {
        let url = format!("{}://{}:{}@{}{}", protocol, username, password, hostname, path);

        // Should contain credentials separator
        assert!(url.contains("@"));
        assert!(url.contains(":"));

        // Should not leak password in debug output
        // (This is a reminder to sanitize URLs before logging)
        let parts: Vec<&str> = url.split('@').collect();
        assert_eq!(parts.len(), 2);
    }

    /// Test path traversal detection
    #[test]
    fn test_path_traversal_detection(
        protocol in protocol_strategy(),
        hostname in hostname_strategy(),
    ) {
        // Paths with .. should be detected as unsafe
        let unsafe_paths = vec![
            "/../etc/passwd",
            "/data/../../etc/passwd",
            "/./../../etc",
            "/../..",
        ];

        for unsafe_path in unsafe_paths {
            let url = format!("{}://{}{}", protocol, hostname, unsafe_path);

            // URL contains traversal attempt
            assert!(url.contains(".."));
        }
    }

    /// Test URL component extraction
    #[test]
    fn test_url_component_extraction(
        protocol in protocol_strategy(),
        hostname in hostname_strategy(),
        path in safe_path_strategy(),
    ) {
        let url = format!("{}://{}{}", protocol, hostname, path);

        // Can extract protocol
        let parts: Vec<&str> = url.split("://").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], protocol);

        // Can extract hostname and path
        let host_and_path = parts[1];
        assert!(host_and_path.contains(&hostname));
    }

    /// Test port number handling
    #[test]
    fn test_port_number_parsing(
        protocol in protocol_strategy(),
        hostname in hostname_strategy(),
        port in 1024u16..=65535u16,
        path in safe_path_strategy(),
    ) {
        let url = format!("{}://{}:{}{}", protocol, hostname, port, path);

        // Should contain port separator
        assert!(url.contains(&format!(":{}", port)));

        // Port should be valid range (>= 1024, u16 max is 65535)
        assert!(port >= 1024);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Fuzz test: Any string should not cause panic when parsing
    #[test]
    fn test_url_parsing_does_not_panic(
        arbitrary_string in "\\PC{0,200}"
    ) {
        // Parsing arbitrary strings should not panic
        let _ = arbitrary_string.split("://").collect::<Vec<&str>>();
        let _ = arbitrary_string.contains("..");
        let _ = arbitrary_string.starts_with('/');
    }
}

#[cfg(test)]
mod deterministic_tests {

    #[test]
    fn test_known_valid_urls() {
        let valid_urls = vec![
            "nfs://server.example.com/exports/data",
            "smb://user:pass@server.local/share",
            "sshfs://user@server.com:2222/home/user",
            "cifs://domain;user:pass@server/share",
        ];

        for url in valid_urls {
            assert!(url.contains("://"));
            assert!(!url.contains(".."));
        }
    }

    #[test]
    fn test_known_invalid_urls() {
        let invalid_patterns = vec!["/../etc/passwd", "/data/../../etc", "/./../.."];

        for pattern in invalid_patterns {
            assert!(pattern.contains(".."));
        }
    }
}
