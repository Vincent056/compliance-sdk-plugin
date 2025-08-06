# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the scanner server
RUN go build -o scanner-server ./cmd/server

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/scanner-server /app/scanner-server

# Change ownership
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose port
EXPOSE 8080

# Run the server
ENTRYPOINT ["/app/scanner-server"] 