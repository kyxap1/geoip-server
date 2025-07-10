# GeoIP Server

A high-performance GeoIP server built with Go that provides IP geolocation information using MaxMind's free GeoLite2 databases. The server supports multiple output formats (JSON, XML, CSV) and includes automatic database updates, TLS support, and comprehensive logging.

## Features

- 🌍 **Multiple Output Formats**: JSON, XML, and CSV responses
- 🔄 **Auto-Updates**: Configurable automatic database updates with cron scheduling
- 🔒 **TLS Support**: Self-signed certificate generation and custom certificate support
- 📊 **Comprehensive Logging**: Nginx-style access logs with customizable formats
- 🐳 **Docker Support**: Multi-stage Alpine-based Docker image
- 🔧 **CLI Interface**: Full command-line interface for configuration
- 🏃 **High Performance**: Optimized for low latency and high throughput
- 🛡️ **Security**: Built-in rate limiting and security headers
- 📈 **Monitoring**: Health check endpoints and metrics
- ✅ **Database Integrity**: SHA256 checksum verification and corruption detection
- 🔄 **Backup & Rollback**: Automatic backups with rollback capabilities
- 🔍 **Status Monitoring**: Real-time database status and health checks

## Quick Start

### Using Docker

```bash
# Run with Docker
docker run -p 8080:80 -e MAXMIND_LICENSE=your_license_key_here geoip-server

# Or use docker-compose
git clone https://github.com/yourusername/golang-geoip.git
cd golang-geoip
cp env.example .env
# Edit .env with your MaxMind license key
docker-compose up
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/golang-geoip.git
cd golang-geoip

# Build
go build -o geoip-server

# Run
./geoip-server --maxmind-license YOUR_LICENSE_KEY
```

## MaxMind License Key

You need a free MaxMind license key to download GeoLite2 databases:

1. Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Generate a license key
3. Set the `MAXMIND_LICENSE` environment variable

## API Endpoints

### JSON Endpoints

Get GeoIP information in JSON format:

```bash
# Get info for client IP
curl http://localhost/
curl http://localhost/json/
curl http://localhost/json

# Get info for specific IP
curl http://localhost/8.8.8.8
curl http://localhost/json/8.8.8.8
```

**Example Response:**
```json
{
  "ip": "8.8.8.8",
  "country": "United States",
  "country_code": "US",
  "region": "California",
  "region_code": "CA",
  "city": "Mountain View",
  "latitude": 37.4056,
  "longitude": -122.0775,
  "postal_code": "94043",
  "timezone": "America/Los_Angeles",
  "asn": 15169,
  "asn_org": "Google LLC",
  "isp": "Google LLC"
}
```

### XML Endpoints

Get GeoIP information in XML format:

```bash
# Get info for client IP
curl http://localhost/xml/
curl http://localhost/xml

# Get info for specific IP
curl http://localhost/xml/8.8.8.8
```

**Example Response:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<geoip>
  <ip>8.8.8.8</ip>
  <country>United States</country>
  <country_code>US</country_code>
  <region>California</region>
  <region_code>CA</region_code>
  <city>Mountain View</city>
  <latitude>37.4056</latitude>
  <longitude>-122.0775</longitude>
  <postal_code>94043</postal_code>
  <timezone>America/Los_Angeles</timezone>
  <asn>15169</asn>
  <asn_org>Google LLC</asn_org>
  <isp>Google LLC</isp>
</geoip>
```

### CSV Endpoints

Get GeoIP information in CSV format:

```bash
# Get info for client IP
curl http://localhost/csv/
curl http://localhost/csv

# Get info for specific IP
curl http://localhost/csv/8.8.8.8
```

**Example Response:**
```csv
ip,country,country_code,region,region_code,city,latitude,longitude,postal_code,timezone,asn,asn_org,isp
8.8.8.8,United States,US,California,CA,Mountain View,37.405600,-122.077500,94043,America/Los_Angeles,15169,Google LLC,Google LLC
```

### Health Check

```bash
curl http://localhost/health
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `80` | HTTP port to listen on |
| `HTTPS_PORT` | `443` | HTTPS port to listen on |
| `ENABLE_TLS` | `false` | Enable TLS/HTTPS |
| `CERT_FILE` | `""` | Path to TLS certificate file |
| `KEY_FILE` | `""` | Path to TLS private key file |
| `CERT_PATH` | `./certs` | Directory to store generated certificates |
| `GENERATE_CERTS` | `false` | Generate self-signed certificates |
| `CERT_VALID_DAYS` | `3650` | Certificate validity period (days) |
| `CERT_HOSTS` | `localhost,127.0.0.1` | Certificate hosts (comma-separated) |
| `DB_PATH` | `./data` | Database storage directory |
| `MAXMIND_LICENSE` | `""` | MaxMind license key (required) |
| `AUTO_UPDATE` | `true` | Enable automatic database updates |
| `UPDATE_INTERVAL` | `0 0 */2 * *` | Update interval (cron format) |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

### CLI Options

```bash
# Server options
./geoip-server --port 80 --https-port 443 --enable-tls

# Database options
./geoip-server --maxmind-license YOUR_KEY --db-path ./data --auto-update

# TLS options
./geoip-server --generate-certs --cert-valid-days 365 --cert-hosts "example.com,localhost"
./geoip-server --cert-path "/etc/ssl/certs" --cert-file "server.crt" --key-file "server.key"

# Update databases manually
./geoip-server update

# Check database status and integrity
./geoip-server status

# Rollback databases to previous backup
./geoip-server rollback

# Certificate management
./geoip-server cert generate --cert-path "/custom/path" --cert-hosts "example.com,192.168.1.1"
./geoip-server cert generate --cert-file "/custom/cert.pem" --key-file "/custom/key.pem"
./geoip-server cert info --cert-path "/custom/path"
./geoip-server cert info --cert-file "/custom/cert.pem" --key-file "/custom/key.pem"

# Show version
./geoip-server version
```

## Database Integrity & Backup

### Checksum Verification

The server automatically verifies database integrity using SHA256 checksums:

- **Download Verification**: Each database is verified after download
- **Integrity Checks**: Regular integrity checks during startup and updates
- **Corruption Detection**: Automatic detection of corrupted databases
- **Rollback Protection**: Invalid databases are automatically rolled back

### Automatic Backups

Database backups are created automatically before each update:

- **Backup Creation**: Automatic backup before database updates
- **Backup Retention**: Keeps the last 5 backup sets
- **Timestamp Tracking**: Backups are timestamped for easy identification
- **Cleanup**: Old backups are automatically cleaned up

### Database Status

Check the current status of all databases:

```bash
./geoip-server status
```

**Example Output:**
```
Database Status:
================

GeoLite2-City:
  Status: Available
  Size: 45123456 bytes
  Modified: 2024-01-15 12:34:56
  Integrity: Valid
  Checksum: a1b2c3d4...

GeoLite2-Country:
  Status: Available
  Size: 2145678 bytes
  Modified: 2024-01-15 12:34:56
  Integrity: Valid
  Checksum: e5f6g7h8...

GeoLite2-ASN:
  Status: Available
  Size: 3456789 bytes
  Modified: 2024-01-15 12:34:56
  Integrity: Valid
  Checksum: i9j0k1l2...
```

### Database Rollback

If a database becomes corrupted or an update fails, you can rollback to the previous version:

```bash
./geoip-server rollback
```

The rollback process:
1. Finds the most recent backup
2. Verifies backup integrity
3. Restores databases from backup
4. Validates restored databases
5. Reloads the server if running

### Integrity Features

- **SHA256 Checksums**: All databases have SHA256 checksums for integrity verification
- **Functional Testing**: Databases are tested with sample queries after download
- **Automatic Rollback**: Failed updates trigger automatic rollback
- **Backup Verification**: Backups are verified before restoration
- **Corruption Detection**: Real-time detection of database corruption

## Docker Deployment

### Docker Compose

```yaml
version: '3.8'

services:
  geoip-server:
    image: geoip-server:latest
    environment:
      - MAXMIND_LICENSE=your_license_key
      - PORT=80
      - LOG_LEVEL=info
    volumes:
      - geoip-data:/app/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./certs:/etc/nginx/certs
    depends_on:
      - geoip-server
    restart: unless-stopped

volumes:
  geoip-data:
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: geoip-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: geoip-server
  template:
    metadata:
      labels:
        app: geoip-server
    spec:
      containers:
      - name: geoip-server
        image: geoip-server:latest
        ports:
        - containerPort: 80
        env:
        - name: MAXMIND_LICENSE
          valueFrom:
            secretKeyRef:
              name: maxmind-secret
              key: license-key
        - name: PORT
          value: "80"
        - name: LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: geoip-data
          mountPath: /app/data
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
      volumes:
      - name: geoip-data
        persistentVolumeClaim:
          claimName: geoip-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: geoip-service
spec:
  selector:
    app: geoip-server
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

## Database Updates

The server automatically downloads and updates MaxMind GeoLite2 databases:

- **GeoLite2-City**: City-level location data
- **GeoLite2-Country**: Country-level location data  
- **GeoLite2-ASN**: Autonomous System Number data

### Update Schedule

By default, databases are updated every 2 days. You can customize this using cron format:

```bash
# Daily at 2 AM
UPDATE_INTERVAL="0 2 * * *"

# Weekly on Sunday at 3 AM
UPDATE_INTERVAL="0 3 * * 0"

# Monthly on the 1st at 4 AM
UPDATE_INTERVAL="0 4 1 * *"
```

### Manual Updates

```bash
# Update databases now
./geoip-server update

# Check update status
./geoip-server update --check-only
```

## TLS/HTTPS Support

### Self-Signed Certificates

Generate certificates with automatic 400 permissions for security:

```bash
# Generate certificate with default settings (./certs directory)
./geoip-server cert generate --cert-hosts "example.com,localhost,127.0.0.1"

# Generate certificate to custom directory
./geoip-server cert generate --cert-path "/etc/ssl/private" --cert-hosts "myserver.com,192.168.1.100"

# Generate certificate with custom validity period
./geoip-server cert generate --cert-valid-days 365 --cert-hosts "short-term.example.com"

# Generate certificate with custom file names
./geoip-server cert generate --cert-file "/custom/server.crt" --key-file "/custom/server.key"

# Enable HTTPS with automatic certificate generation
./geoip-server --enable-tls --generate-certs
```

### Certificate Information

View detailed certificate information including file paths:

```bash
# View certificate info (default path)
./geoip-server cert info

# View certificate info from custom directory
./geoip-server cert info --cert-path "/etc/ssl/private"

# View certificate info for specific files
./geoip-server cert info --cert-file "/custom/server.crt" --key-file "/custom/server.key"
```

**Example Output:**
```
Certificate Information:
  Certificate Path: /etc/ssl/private/server.crt
  Private Key Path: /etc/ssl/private/server.key
  Subject: O=GeoIP Service,C=US
  Issuer: O=GeoIP Service,C=US
  Valid From: 2024-01-15 10:30:45 +0000 UTC
  Valid Until: 2034-01-13 10:30:45 +0000 UTC
  DNS Names: [example.com localhost]
  IP Addresses: [127.0.0.1 192.168.1.100]
```

### Security Features

- **Secure Permissions**: Generated certificates automatically have 400 permissions (read-only owner)
- **Safe Regeneration**: Existing certificates with 400 permissions can be safely regenerated
- **MaxMind License Masking**: License keys are masked in help output (shows only first 10 + last 3 characters)

### Custom Certificates

```bash
# Use custom certificates
./geoip-server --enable-tls --cert-file /path/to/cert.pem --key-file /path/to/key.pem

# Use custom certificate directory
./geoip-server --enable-tls --cert-path "/etc/ssl/certs"
```

### Let's Encrypt with Docker

```yaml
version: '3.8'

services:
  geoip-server:
    image: geoip-server:latest
    environment:
      - MAXMIND_LICENSE=your_license_key
      - ENABLE_TLS=true
      - CERT_FILE=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
      - KEY_FILE=/etc/letsencrypt/live/yourdomain.com/privkey.pem
    volumes:
      - ./letsencrypt:/etc/letsencrypt:ro
      - geoip-data:/app/data
    restart: unless-stopped

volumes:
  geoip-data:
```

## Monitoring and Logging

### Health Checks

```bash
# Simple health check
curl http://localhost/health

# Docker health check
docker run --rm geoip-server wget --no-verbose --tries=1 --spider http://localhost:80/health
```

### Logs

The server uses nginx-style access logs:

```
localhost:80 192.168.1.100 - - [15/Jan/2024:10:30:15 +0000] "GET /json/8.8.8.8 HTTP/1.1" 200 245 "-" "curl/7.68.0"
```

### Metrics

Basic metrics are available through logs and can be integrated with monitoring systems:

- Request count and response times
- Database update status
- Error rates
- Certificate expiration dates

## Performance Tuning

### Docker Resource Limits

```yaml
services:
  geoip-server:
    image: geoip-server:latest
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
```

### Nginx Caching

```nginx
# Cache GeoIP responses
location / {
    proxy_pass http://geoip-server;
    proxy_cache_valid 200 302 10m;
    proxy_cache_valid 404 1m;
}
```

### Database Optimization

- Store databases on SSD storage
- Use memory-mapped files for better performance
- Schedule updates during low-traffic periods

## Security

### Rate Limiting

Built-in rate limiting prevents abuse:

- API endpoints: 10 requests/second per IP
- Health check: 30 requests/second per IP

### Security Headers

The server includes security headers:

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Firewall Rules

```bash
# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Deny direct access to application port (if using nginx proxy)
ufw deny 8080/tcp
```

## Development

### Building

```bash
# Build for current platform
go build -o geoip-server

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o geoip-server

# Build with optimizations
go build -ldflags="-s -w" -o geoip-server
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

### Docker Build

```bash
# Build image
docker build -t geoip-server:latest .

# Multi-architecture build
docker buildx build --platform linux/amd64,linux/arm64 -t geoip-server:latest .
```

## Troubleshooting

### Common Issues

**Database Download Fails**
```bash
# Check license key
./geoip-server update --debug

# Verify network connectivity
curl -I https://download.maxmind.com/
```

**High Memory Usage**
```bash
# Check database file sizes
du -h ./data/

# Monitor memory usage
docker stats geoip-server
```

**TLS Certificate Issues**
```bash
# Check certificate validity
./geoip-server cert info

# Regenerate certificates
./geoip-server cert generate --force
```

### Logs and Debugging

```bash
# Enable debug logging
LOG_LEVEL=debug ./geoip-server

# View Docker logs
docker logs geoip-server

# Follow logs in real-time
docker logs -f geoip-server
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style

- Follow Go conventions
- Use `gofmt` for formatting
- Add comments for public functions
- Write tests for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MaxMind](https://www.maxmind.com/) for providing free GeoLite2 databases
- [Go GeoIP2](https://github.com/oschwald/geoip2-golang) library
- [Gorilla Mux](https://github.com/gorilla/mux) for HTTP routing
- [Cobra](https://github.com/spf13/cobra) for CLI interface

## Support

- GitHub Issues: [https://github.com/yourusername/golang-geoip/issues](https://github.com/yourusername/golang-geoip/issues)
- Documentation: [https://github.com/yourusername/golang-geoip/wiki](https://github.com/yourusername/golang-geoip/wiki)
- Docker Hub: [https://hub.docker.com/r/yourusername/geoip-server](https://hub.docker.com/r/yourusername/geoip-server)
