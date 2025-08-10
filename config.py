{
    "max_workers": 10,
    "timeout": 30,
    "rate_limit": 1.0,
    "user_agent": "Wayback-Tool/2.0",
    "exclude_extensions": [".css", ".js", ".ico", ".png", ".jpg", ".gif"],
    "dangerous_extensions": [
        ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif",
        ".vbs", ".ps1", ".jar", ".reg", ".dll", ".sys"
    ],
    "security_scan": {
        "enabled": true,
        "max_file_size": 50000000,
        "scan_urls": true,
        "scan_content": true
    },
    "database_file": "wayback_data.db"
}
