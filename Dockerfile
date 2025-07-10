# Multi-stage Dockerfile for GeoIP Server
# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

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


########## Stage 2: Create minimal runtime image ##########
FROM amazonlinux:2023

# Install runtime dependencies
RUN dnf install -y ca-certificates tzdata wget bash shadow-utils && \
    dnf clean all

# Create non-root user
RUN groupadd -g 1000 geoip && \
    useradd -r -d /app -s /bin/bash -u 1000 -g geoip geoip

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/geoip-server /usr/local/bin

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create data directory
RUN mkdir -p /app/data && \
    chown -R geoip:geoip /app

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

# run dist upgrade
ARG DATE
ARG UPGRADE=true
RUN if [[ ${UPGRADE} == true ]]; then \
  echo $DATE >/dev/null && dnf update -y --releasever=latest; \
fi

# Switch to non-root user
USER geoip

# Default command
CMD ["geoip-server"]
