# MCP Filesystem Bedrock

This repository contains a Model Context Protocol (MCP) client for filesystem interactions using AWS Bedrock.

## Setup

1. Clone this repository
2. Install dependencies:
```bash
npm install @modelcontextprotocol/inspector
pip install -r requirements.txt
```

## MCP Client Configuration

The MCP client is configured using `mcp.json`. The configuration includes:

- Server type: filesystem
- Port: 8080
- Allowed file extensions: .txt, .json, .md, .csv, .yml, .yaml
- Root directory for file operations: ./data

## Running the MCP Inspector

To run the MCP client inspector, use:

```bash
npx @modelcontextprotocol/inspector --config mcp.json --server filesystem
```

This will start a server on http://localhost:8080 that can interact with your filesystem based on the configuration in mcp.json.

## OpenAPI Schema

The `schemas` directory contains an OpenAPI schema used for AWS Bedrock action group definition via inline schema.

## Python Client

The repository includes a Python client (`client.py`) that interacts with the filesystem through the MCP protocol.

### Usage

```python
from src.client import FilesystemClient

# Initialize the client
client = FilesystemClient("http://localhost:8080")

# List files in a directory
files = client.list_files("/path/to/directory")

# Read a file
content = client.read_file("/path/to/file.txt")

# Write to a file
client.write_file("/path/to/new_file.txt", "File content")
```

## License

MIT
