# GeoIP Server

A high-performance GeoIP server built with Go that provides IP geolocation information using MaxMind's free GeoLite2 databases. The server supports multiple output formats (JSON, XML, CSV) and includes automatic database updates, TLS support, and comprehensive logging.

[![CI/CD Pipeline](https://github.com/kyxap1/geoip-server/workflows/Build%20and%20Push%20Docker%20Image/badge.svg)](https://github.com/kyxap1/geoip-server/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/kyxap1/geoip-server)](https://goreportcard.com/report/github.com/kyxap1/geoip-server)
[![Coverage](https://img.shields.io/badge/Coverage-59.0%25-brightgreen.svg)](https://github.com/kyxap1/geoip-server)

## Features

- **Multiple Output Formats**: JSON, XML, and CSV responses
- **Auto-Updates**: Configurable automatic database updates with cron scheduling
- **Backup & Rollback**: Automatic backups with rollback capabilities
- **TLS Support**: Self-signed certificate generation and custom certificate support
- **Comprehensive Logging**: Nginx-style access logs with customizable formats
- **Docker Support**: Multi-stage Amazon Linux 2023-based Docker image
- **CLI Interface**: Full command-line interface for configuration
- **High Performance**: Optimized for low latency and high throughput
- **Security**: Built-in rate limiting and security headers
- **Monitoring**: Health check endpoints and metrics
- **Database Integrity**: SHA256 checksum verification and corruption detection

## Quick Start

### Using Docker

```bash
# Run with Docker
docker run -p 8080:80 -e MAXMIND_LICENSE=your_license_key_here geoip-server

# Or use docker-compose
git clone https://github.com/kyxap1/geoip-server.git
cd geoip-server
cp env.example .env
# Edit .env with your MaxMind license key
docker-compose up
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/kyxap1/geoip-server.git
cd geoip-server

# Install dependencies
make deps

# Build
make build

# Run tests
make test

# Run with coverage
make test-coverage

# Run
./geoip-server --maxmind-license YOUR_LICENSE_KEY
```

## Development

### Build Commands

```bash
# Build
make build         # Build the application
make test          # Run tests
make lint          # Run golangci-lint
make docker-build  # Build Docker image
```

## MaxMind License Key

You need a free MaxMind license key to download GeoLite2 databases:

1. Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Generate a license key
3. Set the `MAXMIND_LICENSE` environment variable

## API Endpoints

```bash
# JSON format (default)
curl http://localhost/8.8.8.8
curl http://localhost/json/8.8.8.8

# XML format
curl http://localhost/xml/8.8.8.8

# CSV format
curl http://localhost/csv/8.8.8.8

# Health check
curl http://localhost/health
```

**Example JSON Response:**
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

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `80` | HTTP port to listen on |
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
| `CACHE_ENABLED` | `true` | Enable IP caching |
| `CACHE_TTL` | `1h` | Cache TTL duration |
| `CACHE_MAX_ENTRIES` | `10000` | Maximum cache entries |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

### CLI Usage

```bash
# Basic usage
./geoip-server --maxmind-license YOUR_KEY

# With custom ports
./geoip-server -p 8080 --https-port 8443 --enable-tls

# Commands
./geoip-server update     # Update databases
./geoip-server status     # Check status
./geoip-server version    # Show version
```

## Database Management

The server automatically downloads and updates MaxMind GeoLite2 databases with integrity verification and backup support.

```bash
./geoip-server update     # Update databases
./geoip-server status     # Check database status
./geoip-server rollback   # Rollback to previous version
```

## Docker Deployment

```bash
# Run with Docker
docker run -p 8080:80 -e MAXMIND_LICENSE=your_license_key kyxap/geoip-server

# Or use docker-compose
docker-compose up
```



## TLS/HTTPS Support

```bash
# Enable HTTPS with self-signed certificates
./geoip-server --enable-tls --generate-certs

# Use custom certificates
./geoip-server --enable-tls --cert-file /path/to/cert.pem --key-file /path/to/key.pem

# Certificate management
./geoip-server cert generate  # Generate certificates
./geoip-server cert info      # View certificate info
```



## Development

```bash
# Build and test
make build
make test
make lint
make docker-build

# Manual build
go build -o geoip-server
go test ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run `make test` and `make lint`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MaxMind](https://www.maxmind.com/) for providing free GeoLite2 databases
- [Go GeoIP2](https://github.com/oschwald/geoip2-golang) library
- [Gorilla Mux](https://github.com/gorilla/mux) for HTTP routing
- [Cobra](https://github.com/spf13/cobra) for CLI interface

## Support

- GitHub Issues: [https://github.com/kyxap1/geoip-server/issues](https://github.com/kyxap1/geoip-server/issues)
- Documentation: [https://github.com/kyxap1/geoip-server/wiki](https://github.com/kyxap1/geoip-server/wiki)
- Docker Hub: [https://hub.docker.com/r/kyxap/geoip-server](https://hub.docker.com/r/kyxap/geoip-server)
- GitHub Actions: [https://github.com/kyxap1/geoip-server/actions](https://github.com/kyxap1/geoip-server/actions)
