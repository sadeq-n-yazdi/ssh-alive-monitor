# SSH Monitor Test Suite

This directory contains integration tests for the SSH Alive Monitor project. The tests are organized by feature set.

## Organization

*   **`basic/`**: Core API functionality tests.
    *   `test_api.sh`: Basic verification of Host management (Add/Delete) and Results retrieval.
*   **`features/`**: Tests for specific or advanced features.
    *   `test_new_features.sh`: Tests API Key management (Master vs Normal), Response formats (JSON/YAML), and filtering.
    *   `test_cidr_and_pool.sh`: Tests CIDR range expansion, Normal User CIDR limits (/24 limit), and worker pool queuing.
*   **`ssl/`**: SSL/TLS related tests.
    *   `test_ssl.sh`: Tests self-signed certificate generation and HTTPS server startup.

## How to Run Tests

**Important:** All test scripts MUST be run from the **project root directory** to correctly locate the `webserver` source code and build artifacts.

### Prerequisites
*   `go` compiler installed.
*   `curl` and `grep` available.
*   `jq` is recommended for JSON output formatting but tests should run without it (output might be raw).

### Usage

**1. Run Basic API Test:**
```bash
./tests/basic/test_api.sh
```

**2. Run Feature Tests:**
```bash
./tests/features/test_new_features.sh
./tests/features/test_cidr_and_pool.sh
```

**3. Run SSL Test:**
```bash
./tests/ssl/test_ssl.sh
```

## Test Logic

Each script typically follows this pattern:
1.  **Build**: Compiles the Go binary (`webserver/go build ...`).
2.  **Start**: Runs the server in the background (using `&`) on a test port (e.g., 8082, 8083).
3.  **Execute**: Uses `curl` to send HTTP requests to the API.
4.  **Verify**: Checks HTTP status codes or response content (using `grep`) to validate behavior.
5.  **Cleanup**: Kills the background server process on exit.

## Verification

*   **PASS**: The script will output "PASS" or show the expected data.
*   **FAIL**: The script will output "FAIL" or error messages if a check fails.
*   **Logs**: The server logs are output to stdout/stderr, allowing you to see internal behavior (e.g., "Added host...", "Check result...").

