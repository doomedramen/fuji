//! Performance benchmarks for mount operations
//!
//! Measures performance of core Fuji operations to detect regressions

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use fuji::config::Config;
use fuji::mount::options::MountOptionParser;
use std::time::Duration;

/// Benchmark config file loading and parsing
fn bench_config_load(c: &mut Criterion) {
    c.bench_function("config_load_default", |b| {
        b.iter(|| {
            let config = Config::default();
            black_box(config);
        });
    });
}

/// Benchmark mount option parsing
fn bench_mount_options_parse(c: &mut Criterion) {
    let parser = MountOptionParser::new();
    let mut group = c.benchmark_group("mount_options_parse");

    group.bench_function("empty_options", |b| {
        b.iter(|| {
            let options = parser.parse(black_box(""), black_box("nfs"));
            let _ = black_box(options);
        });
    });

    group.bench_function("multiple_nfs_options", |b| {
        b.iter(|| {
            let options = parser.parse(black_box("rw,noatime,vers=4,proto=tcp"), black_box("nfs"));
            let _ = black_box(options);
        });
    });

    group.bench_function("smb_options_with_creds", |b| {
        b.iter(|| {
            let options = parser.parse(
                black_box("username=test,password=pass,uid=1000,gid=1000"),
                black_box("cifs"),
            );
            let _ = black_box(options);
        });
    });

    group.finish();
}

/// Benchmark URL parsing for different protocols
fn bench_url_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_parsing");

    group.bench_function("nfs_url", |b| {
        b.iter(|| {
            let url = black_box("nfs://server.example.com/exports/data");
            // Simple parse to validate format
            let parts: Vec<&str> = url.split("://").collect();
            black_box(parts);
        });
    });

    group.bench_function("smb_url_with_creds", |b| {
        b.iter(|| {
            let url = black_box("smb://user:pass@server.example.com/share");
            let parts: Vec<&str> = url.split("://").collect();
            black_box(parts);
        });
    });

    group.bench_function("sshfs_url", |b| {
        b.iter(|| {
            let url = black_box("sshfs://user@server.example.com/path/to/dir");
            let parts: Vec<&str> = url.split("://").collect();
            black_box(parts);
        });
    });

    group.finish();
}

/// Benchmark path validation
fn bench_path_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_validation");

    group.bench_function("safe_path", |b| {
        b.iter(|| {
            let path = black_box("/mnt/fuji/test-mount");
            let is_safe = !path.contains("..") && path.starts_with('/');
            black_box(is_safe);
        });
    });

    group.bench_function("traversal_attempt", |b| {
        b.iter(|| {
            let path = black_box("/mnt/fuji/../../etc/passwd");
            let is_safe = !path.contains("..") && path.starts_with('/');
            black_box(is_safe);
        });
    });

    group.finish();
}

/// Benchmark JSON serialization for status responses
fn bench_json_serialization(c: &mut Criterion) {
    use serde_json::json;

    let mut group = c.benchmark_group("json_serialization");

    group.bench_function("single_mount_status", |b| {
        b.iter(|| {
            let status = json!({
                "mount_id": "test-mount-123",
                "url": "nfs://server/export",
                "mount_point": "/mnt/fuji/test-mount-123",
                "status": "Active",
                "protocol": "NFS",
            });
            black_box(status);
        });
    });

    group.bench_function("multiple_mounts_status", |b| {
        b.iter(|| {
            let status = json!({
                "mounts": [
                    {
                        "mount_id": "mount-1",
                        "url": "nfs://server1/export",
                        "status": "Active",
                    },
                    {
                        "mount_id": "mount-2",
                        "url": "smb://server2/share",
                        "status": "Active",
                    },
                    {
                        "mount_id": "mount-3",
                        "url": "sshfs://server3/path",
                        "status": "Reconnecting",
                    },
                ]
            });
            black_box(status);
        });
    });

    group.finish();
}

/// Benchmark config file serialization
fn bench_config_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_serialization");

    group.bench_function("config_to_toml", |b| {
        b.iter(|| {
            let config = Config::default();
            let toml = toml::to_string(&config).unwrap();
            black_box(toml);
        });
    });

    group.bench_function("config_from_toml", |b| {
        let toml_str = r#"
            [daemon]
            socket_path = "/tmp/fuji.sock"
            pid_file = "/tmp/fuji.pid"

            [logging]
            level = "info"

            [resource_limits]
            max_mounts = 100
        "#;

        b.iter(|| {
            let config: Result<Config, _> = toml::from_str(black_box(toml_str));
            let _ = black_box(config);
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        bench_config_load,
        bench_mount_options_parse,
        bench_url_parsing,
        bench_path_validation,
        bench_json_serialization,
        bench_config_serialization,
}

criterion_main!(benches);
