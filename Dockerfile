# Multi-stage Dockerfile for GeoIP Server
# Stage 1: Build the application
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set the working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o geoip-server .

# Stage 2: Create minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata wget

# Create non-root user
RUN addgroup -g 1000 geoip && \
    adduser -D -s /bin/sh -u 1000 -G geoip geoip

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/geoip-server .

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create data directory
RUN mkdir -p /app/data && \
    chown -R geoip:geoip /app

# Switch to non-root user
USER geoip

# Expose ports
EXPOSE 80 443

# Set environment variables
ENV GIN_MODE=release
ENV LOG_LEVEL=info
ENV PORT=80
ENV HTTPS_PORT=443
ENV DB_PATH=/app/data

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:$PORT/health || exit 1

# Default command
CMD ["./geoip-server"]
