Check if HOST:PORT listening to SSH or not

Read list of IP addresses and try to make connection and check if it can see SSH init string in certain time or not.

## Go
### Build

```bash
go build -o ssh-alive-check
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

