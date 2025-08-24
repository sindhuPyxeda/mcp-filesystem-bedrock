# MCP Filesystem Bedrock

This repository contains a Model Context Protocol (MCP) client for filesystem interactions using AWS Bedrock. It enables AI agents on AWS Bedrock to access and manipulate files on your local filesystem through a standardized interface.

## Prerequisites

1. **Node.js and npm** (v14 or newer)
   - Required for running the MCP filesystem server
   - [Download and install from nodejs.org](https://nodejs.org/)

2. **Python** (3.8 or newer)
   - Required for running the Python client
   - [Download and install from python.org](https://python.org/)

3. **AWS Account with Bedrock access**
   - You'll need access to AWS Bedrock service and permissions to create and use agents
   - Configure your AWS credentials using AWS CLI or environment variables

## Installation

1. Clone this repository:
```bash
git clone https://github.com/sindhuPyxeda/mcp-filesystem-bedrock.git
cd mcp-filesystem-bedrock
```

2. Install Node.js dependencies:
```bash
npm install -g @modelcontextprotocol/server-filesystem
npm install @modelcontextprotocol/inspector
```

3. Install Python dependencies:
```bash
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

## AWS Bedrock Agent Setup

1. In the AWS Bedrock console, create a new agent

2. Create an action group using the OpenAPI schema in `schemas/filesystem_openapi.json`
   - Action Group Name: FileSystem
   - Description: Provides file system access capabilities
   - Schema source: Select "Inline schema" and paste the contents of the schema file

3. Configure necessary API destination for the action group (if needed)

4. Ensure the agent has appropriate permissions to call the APIs

5. Create an agent alias for testing

6. Note the agent ID and agent alias ID for use with the Python client

## OpenAPI Schema

The `schemas` directory contains an OpenAPI schema (`filesystem_openapi.json`) used for AWS Bedrock action group definition via inline schema. This schema defines the endpoints that allow the Bedrock agent to interact with your filesystem.

## Python Client

The repository includes a Python client (`src/client.py`) that integrates with AWS Bedrock agents through the MCP protocol.

### Configuration

Edit the client.py file to configure your filesystem directories:

```python
# Root directories that the filesystem server will have access to
FILESYSTEM_DIRS = [
    "/path/to/your/directory1",
    "/path/to/your/directory2",
]

# AWS credentials configuration
AWS_PROFILE = "your-aws-profile"  # AWS profile to use for authentication
AWS_REGION  = "us-east-1"        # AWS region for Bedrock service
```

### Usage

1. Start the MCP filesystem server:
   ```bash
   npx @modelcontextprotocol/server-filesystem /path/to/your/directory1 /path/to/your/directory2
   ```

2. Run the Python client with your AWS Bedrock agent ID and alias:
   ```bash
   python src/client.py YOUR_AGENT_ID YOUR_AGENT_ALIAS_ID
   ```

3. Enter prompts to interact with the agent, which will have access to your filesystem through the MCP protocol.

## License

MIT
