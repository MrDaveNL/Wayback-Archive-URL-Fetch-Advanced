# Wayback-Archive-URL-Fetch-Advanced
The Wayback Archive URL Fetch Advanced

# Wayback Scraper Advanced

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Security](https://img.shields.io/badge/security-enhanced-red.svg)

**Advanced Wayback Machine Analysis Tool with Enterprise-Grade Security**

A powerful, feature-rich tool for querying and analyzing archived web content from the Internet Archive's Wayback Machine. Built with security-first principles and enterprise functionality.

## ✨ Features

### 🔍 **Advanced Querying**
- Single URL analysis with customizable parameters
- Bulk URL processing with multi-threading
- Date range filtering (from/to dates)
- Custom field selection and data collapse options
- Rate limiting to respect server resources

### 🛡️ **Security First**
- **Malware Protection**: Automatic detection of dangerous file types
- **Content Scanning**: Signature-based malware detection
- **URL Analysis**: Suspicious pattern recognition
- **MIME Type Filtering**: Whitelist-based content type control
- **File Size Limits**: Configurable maximum download sizes
- **Threat Classification**: HIGH/MEDIUM/LOW risk assessment
- **Security Logging**: Comprehensive audit trail

### 🗄️ **Database Management**
- SQLite database for persistent storage
- Query history tracking
- Security event logging
- Data export capabilities (CSV, JSON, TXT)
- Database statistics and cleanup tools

### 📊 **Analytics & Reporting**
- Statistical analysis of archived content
- Timeline visualization by year
- Status code distribution analysis
- File type frequency reports
- Domain analysis
- Security incident reports

### ⚙️ **Configuration Management**
- JSON-based configuration system
- Live settings modification
- Performance tuning options
- Security policy customization
- Default configuration reset

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.7 or higher required
python --version

# Install dependencies
pip install -r requirements.txt
```

### Installation

```bash
# Clone the repository
git clone https://github.com/4apdigital/wayback-scraper.git
cd wayback-scraper

# Install dependencies
pip install requests colorama sqlite3

# Run the tool
python app.py --interactive
```

### Basic Usage

```bash
# Interactive mode (recommended for new users)
python app.py --interactive

# Single URL query
python app.py --url "https://example.com"

# Bulk URL processing
python app.py --bulk urls.txt --output results.json --format json

# Advanced query with date range
python app.py --url "https://example.com" --output filtered_results.csv --format csv
```

## 📖 Usage Guide

### Interactive Mode

Launch the tool in interactive mode for full functionality:

```bash
python app.py --interactive
```

**Menu Options:**
1. 🔍 **Single URL Query** - Analyze individual websites
2. 📋 **Bulk URL Query** - Process multiple URLs simultaneously  
3. 📊 **View Analysis** - Statistical analysis of stored data
4. 🗄️ **Database Management** - Manage stored queries and results
5. ⚙️ **Configuration** - Modify tool settings
6. 📈 **Generate Report** - Create comprehensive reports
7. 🔧 **Advanced Filters** - Custom filtering options
8. 🛡️ **Security Dashboard** - View security events and blocks
9. ❌ **Exit** - Close the application

### Command Line Interface

For automation and scripting:

```bash
# Basic URL query
python app.py --url "https://github.com"

# Bulk processing with custom output
python app.py --bulk url_list.txt --output results.json --format json

# Using custom configuration
python app.py --config custom_config.json --url "https://example.com"
```

### Advanced Query Options

When using single URL queries, you can specify:

- **From Date**: `YYYYMMDD` format (e.g., `20200101`)
- **To Date**: `YYYYMMDD` format (e.g., `20231231`)
- **Result Limit**: Maximum number of results to return
- **Custom Fields**: Specify which data fields to retrieve

## 🔧 Configuration

### Default Configuration

The tool creates a `config.json` file with the following structure:

```json
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
```

### Security Configuration

#### Dangerous File Extensions
The tool automatically blocks these file types:

**Executables:**
- `.exe`, `.msi`, `.bat`, `.cmd`, `.com`, `.scr`, `.pif`

**Scripts:**
- `.vbs`, `.ps1`, `.jar`, `.jse`, `.reg`, `.hta`

**System Files:**
- `.dll`, `.sys`, `.drv`, `.ocx`, `.ax`, `.cpl`

**Macro Documents:**
- `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`, `.potm`

#### MIME Type Filtering
Allowed content types:
- `text/html`, `text/plain`, `text/css`
- `application/json`, `application/xml`, `text/xml`
- `application/pdf`
- `image/jpeg`, `image/png`, `image/gif`, `image/svg+xml`
- `text/javascript`, `application/javascript`

## 🛡️ Security Features

### Threat Detection

**File Signature Analysis:**
- Windows executables (MZ header)
- Linux executables (ELF header)
- Java class files
- Archive files (ZIP, RAR, GZIP)

**Content Scanning:**
- Suspicious JavaScript functions (`eval()`, `base64_decode`)
- Shell execution commands (`shell_exec`, `system()`)
- Script injection patterns

**URL Pattern Analysis:**
- IP addresses instead of domain names
- URL shorteners (bit.ly, tinyurl, t.co)
- Suspicious top-level domains (.tk, .ml, .ga, .cf)
- Extremely long random strings

### Security Dashboard

Access real-time security monitoring:

- **Threat Statistics**: Overview of blocked items by threat level
- **Recent Blocks**: Latest security incidents with timestamps
- **Security Settings**: Current protection configuration
- **Audit Trail**: Complete history of security events

## 📊 Database Schema

### Tables

**queries**
- `id` (PRIMARY KEY)
- `url` (TEXT)
- `timestamp` (DATETIME)
- `results_count` (INTEGER)
- `filters_applied` (TEXT)

**results**
- `id` (PRIMARY KEY)
- `query_id` (FOREIGN KEY)
- `original_url` (TEXT)
- `archived_url` (TEXT)
- `timestamp` (TEXT)
- `status_code` (TEXT)
- `mime_type` (TEXT)

**security_blocks**
- `id` (PRIMARY KEY)
- `url` (TEXT)
- `reason` (TEXT)
- `timestamp` (DATETIME)
- `threat_level` (TEXT)

## 📈 Export Formats

### JSON Format
```json
[
    {
        "original": "https://example.com/page.html",
        "timestamp": "20231215120000",
        "statuscode": "200",
        "mimetype": "text/html",
        "archived_url": "https://web.archive.org/web/20231215120000/https://example.com/page.html"
    }
]
```

### CSV Format
```csv
original,timestamp,statuscode,mimetype,archived_url
https://example.com/page.html,20231215120000,200,text/html,https://web.archive.org/web/20231215120000/https://example.com/page.html
```

### TXT Format
```
https://example.com/page.html | 20231215120000 | 200
https://example.com/other.html | 20231214110000 | 200
```

## 🔍 Use Cases

### Digital Forensics
- Website change tracking
- Content evolution analysis
- Historical preservation research

### Security Research
- Malware hosting history
- Phishing site analysis
- Threat intelligence gathering

### SEO & Marketing
- Competitor website tracking
- Historical content analysis
- Archive-based research

### Academic Research
- Web evolution studies
- Digital archaeology
- Historical content preservation

## 🚨 Important Notes

### Rate Limiting
- Default 1-second delay between requests
- Configurable in settings
- Respects Wayback Machine server limits

### Legal Compliance
- Tool respects robots.txt and server policies
- No copyrighted content reproduction
- Educational and research use intended

### Data Privacy
- No personal data collection
- Local storage only
- User-controlled data retention

## 🐛 Troubleshooting

### Common Issues

**Connection Timeouts:**
```bash
# Increase timeout in config.json
"timeout": 60
```

**Memory Issues with Large Datasets:**
```bash
# Reduce max_workers
"max_workers": 5
```

**Database Locked Errors:**
```bash
# Check for multiple tool instances
ps aux | grep app.py
```

### Error Codes

- **Error 429**: Rate limit exceeded - increase `rate_limit` value
- **Error 503**: Service unavailable - try again later
- **Error timeout**: Network issues - check internet connection

### Logging

Check log files for detailed error information:
- `wayback_tool.log` - General application logs
- `security.log` - Security-related events

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone for development
git clone https://github.com/4apdigital/wayback-scraper.git
cd wayback-scraper

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black app.py
flake8 app.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Internet Archive** - For providing the Wayback Machine API
- **Python Community** - For excellent libraries and tools
- **Security Researchers** - For threat intelligence and best practices

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/MrDaveNL/Wayback-Archive-URL-Fetch-Advanced/tree/main)
- **Issues**: [GitHub Issues](https://github.com/MrDaveNL/Wayback-Archive-URL-Fetch-Advanced/tree/main/issues)

## 🔄 Changelog

### Version 2.0 (Current)
- ✅ Enhanced security scanning
- ✅ Multi-threading support
- ✅ Database integration
- ✅ Advanced reporting
- ✅ Configuration management

### Version 1.1
- ✅ Basic filtering
- ✅ JSON export
- ✅ Command-line interface

### Version 1.0
- ✅ Initial release
- ✅ Basic Wayback Machine queries
- ✅ Simple output formatting

---

**Created with ❤️ by 4ap Digital**

*Empowering digital archaeology and security research through advanced web archive analysis.*
