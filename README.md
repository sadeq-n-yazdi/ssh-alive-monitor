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

#### Setting up GitHub Secrets

To use the deployment workflow, you must add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

1.  `VPS_HOST`: The IP address or hostname of your VPS (e.g., `vps03.example.com`).
2.  `VPS_USERNAME`: The SSH username used to log in (e.g., `root`).
3.  `SSH_PRIVATE_KEY`: Your SSH private key. 
    *   Generate a new key pair on your local machine if you don't have one: `ssh-keygen -t ed25519 -C "github-actions"`
    *   Add the **public key** (`id_ed25519.pub`) to `~/.ssh/authorized_keys` on your VPS.
    *   Paste the **private key** (`id_ed25519`) content into this GitHub secret.

### Initial VPS Setup via GitHub Actions

If you are deploying to a fresh VPS, you can use the manual "setup" workflow to prepare the environment:

1. Go to the **Actions** tab in your GitHub repository.
2. Select the **Deploy to VPS** workflow on the left.
3. Click the **Run workflow** dropdown and select the branch (usually `main`).
4. Click **Run workflow**.

This manual action will:
- Create `/opt/ssh-monitor` on your VPS.
- Build and upload the `ssh-monitor` binary.
- Initialize `config.json` (from sample) if it doesn't already exist.
- Install and link the `ssh-monitor.service`.
- Reload systemd and start the service.

Once the initial setup is complete, subsequent pushes to the `main` branch will automatically update the binary and restart the service.

#### Notes on SSH Setup
- Ensure the user specified in `VPS_USERNAME` has `sudo` privileges without a password for `systemctl` commands if you want the service restart to work automatically.
- Alternatively, you can adjust the `.github/workflows/deploy.yml` to match your specific server permissions.

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

