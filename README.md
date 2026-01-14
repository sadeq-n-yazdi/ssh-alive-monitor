# SSH Alive Check

Version: 0.1.0  
Author: Sadeq N. Yazd

A tool to check if a host is responding with an SSH banner. Includes a CLI and a Web Server for monitoring.

It was created as a hobby and for personal use during the Iran Internet Blackout in January 2024.

## Go
### Build

```bash
cd go-cli && go build -o ../ssh-alive-check
```

### Usage

```bash
# Check hosts from a file
./ssh-alive-check -f test_hosts.txt

# Check hosts from stdin
cat test_hosts.txt | ./ssh-alive-check

# Set custom timeout (default 5s)
./ssh-alive-check -f test_hosts.txt -t 2
```

### Output Format

`HOST:PORT STATUS`

Statuses:
- `SSH`: SSH protocol detected.
- `TIMEOUT`: Connection or read timed out.
- `ACTIVE_REJECT`: Connection refused.
- `PROTOCOL_MISMATCH`: Connected but did not send SSH version string.

## Web Server

The web server provides a REST API to manage hosts and view monitoring results. It features a concurrent worker pool for efficient checking and supports managing hosts via individual IPs or CIDR ranges.

### Installation

#### Automated Installation (Recommended)
Run the `install.sh` script as root. This will build the server, install it to `/opt/ssh-monitor`, and set up a systemd service.
```bash
sudo ./install.sh
```

#### Manual Installation
1. **Build**:
   ```bash
   cd webserver
   go build -o ssh-monitor
   ```
2. **Configure**:
   ```bash
   cp webserver/config.json.sample webserver/config.json
   # Edit config.json with your settings
   ```
3. **Run**:
   ```bash
   ./ssh-monitor -port 8080
   ```

### Authentication & Sessions

All API requests require an API key passed in the `X-API-Key` header or via **HTTP Basic Authentication**.

- **Session Management**: Successful Basic Authentication sets a secure, HTTP-only cookie, allowing seamless access to the web interface without re-entering credentials.
- **Logout**: You can log out by visiting `/logout`, which clears the session cookie.

#### API Key Types
- **Master Key**: Has full access, including managing other API keys and adding large CIDR ranges.
- **Normal Key**: Can manage hosts (restricted to /24 or smaller ranges) and view results, but cannot manage other keys.

#### Key Generation
Use the provided script to generate a secure API key:
```bash
./webserver/generate_key.sh
```

### Configuration

The server reads configuration from `config.json` and `override.json`.

| Field | Description | Default |
|-------|-------------|---------|
| `port` | Port to listen on | `8080` |
| `log_level` | `debug`, `info`, `warning`, `error` | `info` |
| `log_components` | `requests`, `response`, `checks` | all |
| `log_format` | `text`, `json`, `color` | `color` |
| `default_interval` | Interval between checks (e.g., `10m`, `1h`) | `10m` |
| `default_timeout` | Timeout for each SSH check (e.g., `5s`) | `5s` |
| `check_pool_size` | Max total concurrent checks | `100` |
| `max_subnet_concurrency` | Max concurrent checks per /24 subnet | `2` |
| `master_keys` | List of initial master API keys | `["master-key-123"]` |
| `predefined_hosts`| Simple list of hosts visible without an API key | `[]` |
| `hosts` | Detailed list of hosts with custom settings | `[]` |
| `ip_whitelist` | IP ranges allowed to see index page without key | `[]` |

#### Detailed Host Configuration

The `hosts` field allows defining hosts with specific check parameters and visibility:

```json
"hosts": [
    {
        "host": "private-server.com:22",
        "interval": "1m",
        "timeout": "2s",
        "public": false
    },
    {
        "host": "public-server.com",
        "public": true
    }
]
```

- `host`: The address to check (required).
- `interval`: Override `default_interval` (optional).
- `timeout`: Override `default_timeout` (optional).
- `public`: If `true`, visible on the public status page (optional, default `false`).

### Web Interface

The server provides a simple web interface for monitoring and management:
- `/`: Public status page (shows predefined hosts). Shows all hosts if authenticated.
- `/form/`: Management interface (guarded by API Key/Basic Auth).

### API Endpoints & Samples

#### Host Management

- **Add Host (Plain Text)**
  ```bash
  curl -X POST -H "X-API-Key: YOUR_KEY" -d "192.168.1.10:22" http://localhost:8080/api/hosts
  ```

- **Add Host Range (CIDR)**
  ```bash
  # Adds all IPs in the range. Normal users limited to /24 or smaller.
  curl -X POST -H "X-API-Key: YOUR_KEY" -d "192.168.1.0/24" http://localhost:8080/api/hosts
  ```

- **Add Host (JSON with custom settings)**
  ```bash
  curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
       -d '{"host": "google.com:22", "interval": "5m", "timeout": "2s"}' \
       http://localhost:8080/api/hosts
  ```

- **List Monitored Hosts**
  ```bash
  curl -H "X-API-Key: YOUR_KEY" http://localhost:8080/api/hosts
  ```

- **Remove Host**
  ```bash
  curl -X DELETE -H "X-API-Key: YOUR_KEY" -d "google.com:22" http://localhost:8080/api/hosts
  ```

#### Results & Monitoring

- **Get Latest Results (Plain Text)**
  ```bash
  curl -H "X-API-Key: YOUR_KEY" http://localhost:8080/api/results
  ```

- **Get Results (JSON)**
  ```bash
  curl -H "X-API-Key: YOUR_KEY" -H "Accept: application/json" http://localhost:8080/api/results
  # OR
  curl -H "X-API-Key: YOUR_KEY" "http://localhost:8080/api/results?format=json"
  ```

- **Filtering and Limiting**
  ```bash
  # Last 10 results for a specific host from the last hour
  curl -H "X-API-Key: YOUR_KEY" "http://localhost:8080/api/results?host=127.0.0.1&limit=10&since=1h"
  ```

#### API Key Management (Master Only)

- **List Keys**
  ```bash
  curl -H "X-API-Key: MASTER_KEY" http://localhost:8080/api/keys
  ```

- **Add New Key**
  ```bash
  curl -X POST -H "X-API-Key: MASTER_KEY" -H "Content-Type: application/json" \
       -d '{"key": "new-secure-key", "type": "normal"}' \
       http://localhost:8080/api/keys
  ```

## Testing

The project includes a comprehensive test suite located in the `tests/` directory.

To run tests:
```bash
./tests/basic/test_api.sh           # Basic API functionality
./tests/features/test_new_features.sh # Formats, filtering, keys
./tests/features/test_cidr_and_pool.sh # CIDR ranges and concurrency
./tests/ssl/test_ssl.sh             # SSL/TLS verification
```

See `tests/README.md` for more details on test coverage.

## Deployment

### Makefile

A `Makefile` is provided for local builds and manual deployment:

```bash
# Build the web server
make build

# Build and compress with upx
make compress

# Deploy to VPS (requires vps03 to be defined in ~/.ssh/config or environment)
make deploy
```

### Docker

You can run the web server using Docker:

```bash
# Build image
docker build -t ssh-monitor .

# Run container
docker run -d -p 8080:8080 -v $(pwd)/config.json:/app/config.json ssh-monitor
```

### GitHub Actions

The repository includes a GitHub Action for automated deployment to your VPS on every push to the `main` branch.

## Python

### Usage

```bash
# Check hosts from a file
cd python && uv run ssh_alive_check.py ../test_hosts.txt

# Check hosts from stdin
cat test_hosts.txt | python/ssh_alive_check.py

# Set custom timeout (default 5s)
python/ssh_alive_check.py -f test_hosts.txt -t 2
```

### Output Format

`HOST:PORT STATUS`

Statuses:
- `SSH`: SSH protocol detected.
- `TIMEOUT`: Connection or read timed out.
- `ACTIVE_REJECT`: Connection refused.
- `PROTOCOL_MISMATCH`: Connected but did not send SSH version string.


## License

This project is licensed under the [MIT License](LICENSE). 
For more information, see the [official MIT License page](https://opensource.org/license/mit).