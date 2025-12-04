use fuji::mount::drivers::validation::MountUrlValidator;

fn main() {
    let validator = MountUrlValidator::new().unwrap();

    let test_url = "nfs://server.com/../../../../../../../../../../../";

    println!("Testing URL: {}", test_url);
    println!("URL length: {}", test_url.len());
    println!("Contains '..': {}", test_url.contains(".."));

    // Count the occurrences
    let traversal_count = test_url.matches("..").count();
    println!("Traversal count: {}", traversal_count);

    // Test validation
    match validator.validate_url(test_url) {
        Ok(_) => println!("Validation PASSED (should have failed!)"),
        Err(e) => println!("Validation FAILED: {}", e),
    }

    // Test the path component specifically
    if let Ok(parsed) = url::Url::parse(test_url) {
        let path = parsed.path();
        println!("Parsed path: '{}'", path);
        println!("Path length: {}", path.len());

        // Test sanitize_path_component directly
        match validator.sanitize_path_component(path) {
            Ok(sanitized) => println!("Sanitize PASSED: '{}'", sanitized),
            Err(e) => println!("Sanitize FAILED: {}", e),
        }

        // Count traversal in path
        let path_traversal_count = path.matches("..").count();
        println!("Path traversal count: {}", path_traversal_count);
    }
}