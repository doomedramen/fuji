# Running Fuji as a Daemon

Fuji does not include built-in daemonization support. Instead, you should use your platform's standard service manager or process supervisor.

## Development/Testing

For quick testing or development, you can use `nohup`:

```bash
# Start the daemon in the background
nohup ./target/release/fuji daemon start --no-automount > /tmp/fuji.log 2>&1 &

# Check the daemon status
./target/release/fuji status

# View logs
tail -f /tmp/fuji.log

# Stop the daemon
./target/release/fuji daemon stop
```

## Production Deployment

### Linux (systemd)

Create a systemd service file at `/etc/systemd/system/fuji.service`:

```ini
[Unit]
Description=Fuji Network Mount Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=fuji
Group=fuji
ExecStart=/usr/local/bin/fuji daemon start --no-automount
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable fuji
sudo systemctl start fuji
```

### macOS (launchd)

Create a launchd plist file at `~/Library/LaunchAgents/com.github.fuji.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.fuji</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/fuji</string>
        <string>daemon</string>
        <string>start</string>
        <string>--no-automount</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/fuji.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/fuji.log</string>
</dict>
</plist>
```

Load the service:
```bash
launchctl load ~/Library/LaunchAgents/com.github.fuji.plist
launchctl start com.github.fuji
```

### Docker

For Docker deployments, use a supervisord configuration or run the daemon in the foreground:

```dockerfile
# In your Dockerfile
CMD ["fuji", "daemon", "start", "--no-automount"]
```

Or with supervisord:
```ini
[supervisord]
nodaemon=true

[program:fuji]
command=/usr/local/bin/fuji daemon start --no-automount
autorestart=true
stdout_logfile=/var/log/fuji.log
stderr_logfile=/var/log/fuji.log
```

## Why No Built-in Daemonization?

Tokio (the async runtime used by Fuji) cannot properly survive a `fork()` system call, which is required for traditional Unix daemonization. When a process forks after initializing Tokio:

1. The child process inherits corrupted file descriptors
2. The async runtime state becomes invalid
3. I/O operations fail with "Bad file descriptor" errors

Using your platform's native service manager avoids these issues and provides:
- Proper process supervision
- Automatic restarts
- Integrated logging
- Standard startup/shutdown lifecycle management
- Better security isolation

## Tips

1. Always use absolute paths in production
2. Configure proper log rotation
3. Run as a non-root user when possible
4. Use TLS encryption for network shares in production
5. Set up monitoring and alerting for daemon health