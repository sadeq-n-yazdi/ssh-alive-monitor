Check if HOST:PORT listening to SSH or not

Read list of IP addresses and try to make connection and check if it can see SSH init string in certain time or not.

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

The web server provides a REST API to manage hosts and view monitoring results.

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

### Authentication

All API requests require an API key passed in the `X-API-Key` header or via **HTTP Basic Authentication** (use an empty username and the API key as the password).

#### API Key Types
- **Master Key**: Has full access, including managing other API keys.
- **Normal Key**: Can manage hosts and view results, but cannot manage other keys.

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
| `master_keys` | List of initial master API keys | `["master-key-123"]` |
| `predefined_hosts`| Hosts visible without an API key | `[]` |
| `ip_whitelist` | IP ranges allowed to see index page without key | `[]` |

### Web Interface

The server provides a simple web interface for monitoring and management:
- `/`: Public status page (shows predefined hosts). Shows all hosts if authenticated.
- `/form/`: Management interface (guarded by API Key/Basic Auth).

### API Endpoints & Samples

#### Host Management

- **Add Host (Plain Text)**
  ```bash
  curl -X POST -H "X-API-Key: YOUR_KEY" -d "192.168.1.10:22" http://localhost:8080/api/hosts
  # OR using Basic Auth
  curl -u ":YOUR_KEY" -X POST -d "192.168.1.10:22" http://localhost:8080/api/hosts
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

- **Disable/Enable Key**
  ```bash
  curl -X PATCH -H "X-API-Key: MASTER_KEY" -H "Content-Type: application/json" \
       -d '{"key": "some-key", "enabled": false}' \
       http://localhost:8080/api/keys
  ```

- **Delete Key**
  ```bash
  curl -X DELETE -H "X-API-Key: MASTER_KEY" "http://localhost:8080/api/keys?key=some-key"
  ```

## Python

### Usage

```bash
# Check hosts from a file
uv run ssh_alive_check.py test_hosts.txt

# Check hosts from stdin
cat test_hosts.txt | uv run ./ssh_alive_check.py

# Set custom timeout (default 5s)
uv run ./ssh_alive_check.py -f test_hosts.txt -t 2
```

### Output Format

`HOST:PORT STATUS`

Statuses:
- `SSH`: SSH protocol detected.
- `TIMEOUT`: Connection or read timed out.
- `ACTIVE_REJECT`: Connection refused.
- `PROTOCOL_MISMATCH`: Connected but did not send SSH version string.

