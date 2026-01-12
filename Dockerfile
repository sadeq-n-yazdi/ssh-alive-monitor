# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install upx
RUN apk add --no-cache upx

# Copy go.mod first for better caching
COPY webserver/go.mod ./
RUN go mod download

# Copy the rest of the source code
COPY webserver/ ./

# Build the application
RUN go build -ldflags="-s -w" -o ssh-monitor .

# Compress the binary
RUN upx ssh-monitor

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/ssh-monitor .

# Create a placeholder for the config file
# Users should mount their own config.json to /app/config.json
RUN touch config.json

# Expose the default port
EXPOSE 8080

# Run the application
ENTRYPOINT ["./ssh-monitor"]
