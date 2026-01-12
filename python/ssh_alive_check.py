import argparse
import asyncio
import re
import sys
from typing import List, Tuple, Optional

VERSION = "0.1.0"
AUTHOR = "Sadeq <code@sadeq.uk>"
DESCRIPTION = "A lightweight tool to check if a host is responding with an SSH banner."
LICENSE_INFO = "This project is licensed under the MIT License without any liability and/or obligation."

# Regex for matching SSH server string
# Starts with 'SSH-', followed by protocol version, hyphen, software version.
# Example: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
SSH_BANNER_RE = re.compile(rb'^SSH-[0-9.]+-[a-zA-Z0-9 .-]+')

# Regex to capture HOST and optional PORT
# This is a basic extractor. It assumes input lines might contain "HOST:PORT" or "HOST".
# For IPv6, format [HOST]:PORT is standard, but simple HOST:PORT works for IPv4.
# We'll strip whitespace and look for patterns.
def parse_target(line: str) -> Tuple[str, int]:
    """
    Parses a string to extract host and port.
    Defaults to port 22 if not specified.
    Supports:
        1.2.3.4
        1.2.3.4:2222
        example.com
        example.com:2022
    """
    line = line.strip()
    # Check for [IPv6]:port format
    if line.startswith('[') and ']:' in line:
        host_part, port_part = line.rsplit(']:', 1)
        host = host_part.strip('[')
        try:
            port = int(port_part)
        except ValueError:
            port = 22
        return host, port

    # Check for IPv4/Hostname:Port
    if ':' in line:
        # Be careful with IPv6 literals without brackets, though strictly they should be bracketed if port is appended.
        # Assuming standard IPv4 or Hostname here for simplicity as per common CLI tools.
        # If the last part is a number, treat as port.
        host_part, port_part = line.rsplit(':', 1)
        if port_part.isdigit():
            return host_part, int(port_part)
    
    return line, 22

async def check_host(host: str, port: int, timeout: float) -> str:
    """
    Connects to host:port and checks for SSH banner.
    Returns: SSH, TIMEOUT, REFUSED, OTHER, ERROR
    """
    writer = None
    try:
        # Open connection with timeout
        # wait_for is needed for the connection phase itself in some cases, 
        # but open_connection doesn't support timeout arg directly in older python, 
        # but modern asyncio handles it via standard timeout contexts if needed,
        # usually simpler to wrap the whole thing.
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return "TIMEOUT"
        except ConnectionRefusedError:
            return "REFUSED"
        except OSError as e:
            # Catch network unreachable, etc.
            return f"ERROR({e.strerror})"

        # Read initial banner
        try:
            # SSH servers usually send the banner immediately upon connection.
            # We wait up to `timeout` seconds for data.
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            
            if not data:
                return "NODATA"
            
            # Check for SSH pattern
            # Decode carefully or match bytes directly. Regex is bytes, so we match bytes.
            if SSH_BANNER_RE.match(data):
                return "SSH"
            else:
                return "OTHER" # Received data, but didn't match SSH pattern

        except asyncio.TimeoutError:
            return "TIMEOUT" # Connected, but no data received in time
        except Exception as e:
            return f"ERROR_READ({str(e)})"
            
    except Exception as e:
        return f"ERROR_GEN({str(e)})"
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def process_inputs(inputs: List[str], timeout: float):
    tasks = []
    # Deduplicate inputs if needed? Keeping 1-to-1 mapping for output is usually better for CLIs.
    
    results = []
    
    # We can run all in parallel. For very large lists, a semaphore might be needed.
    # Let's add a semaphore to be safe (e.g. 100 concurrent connections).
    sem = asyncio.Semaphore(100)

    async def sem_task(original_line):
        host, port = parse_target(original_line)
        async with sem:
            res = await check_host(host, port, timeout)
            # Format: HOST:PORT result
            print(f"{host}:{port} {res}")

    tasks = [asyncio.create_task(sem_task(line)) for line in inputs if line.strip()]
    await asyncio.gather(*tasks)

def main():
    parser = argparse.ArgumentParser(
        description=f"{DESCRIPTION}\n\nVersion: {VERSION}\nAuthor: {AUTHOR}\n\n{LICENSE_INFO}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_file', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                        help="Input file containing list of IP addresses (one per line). Defaults to stdin.")
    parser.add_argument('-f', '--file', type=argparse.FileType('r'), dest='input_file_flag',
                        help="Input file containing list of IP addresses (alternative to positional argument).")
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help="Timeout in seconds for connection and data read. Default: 5.0")
    
    args = parser.parse_args()

    # Determine input source
    input_file = args.input_file_flag if args.input_file_flag else args.input_file
    
    # Read all lines
    lines = input_file.readlines()
    
    try:
        asyncio.run(process_inputs(lines, args.timeout))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
