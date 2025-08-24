#!/usr/bin/env python3
'''
MCP Filesystem Client for AWS Bedrock

This client bridges AWS Bedrock agents with a local filesystem through the MCP protocol.
It translates RESTful API calls into MCP tool invocations, enabling Bedrock agents to
perform filesystem operations like reading, writing, and searching files.

Usage: python client.py <AGENT_ID> <AGENT_ALIAS_ID>
'''
# Standard library imports for I/O, async operations, and data handling
import os, sys, json, asyncio, base64
from typing import Any, Dict, List, Optional
from types import SimpleNamespace
from urllib.parse import urlparse

# AWS and MCP client dependencies
import boto3
from botocore.config import Config
from mcp.client.stdio import stdio_client  # MCP client for standard I/O communication
from mcp.client.session import ClientSession  # MCP session management

# ========= BASIC CONFIG =========
# Load environment variables from .env file if available
import os
from pathlib import Path
from dotenv import load_dotenv

# Try to load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# AWS credentials and region configuration
AWS_PROFILE = os.environ.get("AWS_PROFILE", "default")  # AWS profile to use for authentication
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")  # AWS region for Bedrock service

# Root directories that the filesystem server will have access to
# These directories will be accessible to the Bedrock agent
filesystem_dirs_str = os.environ.get("FILESYSTEM_DIRS", "")
FILESYSTEM_DIRS = [dir.strip() for dir in filesystem_dirs_str.split(",") if dir.strip()]

# Fallback to default directories if not specified in environment
if not FILESYSTEM_DIRS:
    # Replace these with safe example paths in your home directory
    FILESYSTEM_DIRS = [
        os.path.join(os.path.expanduser("~"), "Documents"),
    ]

# Action group OpenAPI (operationId) names used in your Bedrock schema
# Maps REST API paths to operation IDs defined in the OpenAPI schema
# These are the functions that will be exposed to the Bedrock agent
PATH_TO_OPERATION_ID = {
    "/fs/allowed-roots":    "listAllowedDirectories", # List directories the server has access to
    "/fs/info":             "getFileInfo",             # Get metadata for a file or directory
    "/fs/read":             "readFile",                # Read file contents
    "/fs/list":             "listDirectory",           # List directory contents (optional endpoint)
    "/fs/search":           "searchFiles",             # Search for files by content (optional endpoint)
    "/fs/move":             "moveFile",                # Move/rename files (optional endpoint)
    "/fs/edit":             "editFile",                # Edit file contents (optional endpoint)
    "/fs/write":            "writeFile",               # Write to a file (optional endpoint)
    "/fs/create-directory": "createDirectory",         # Create a directory (optional endpoint)
}

# Map API paths → underlying MCP tools
# Translates REST API paths to the corresponding MCP tool names
# These MCP tools are provided by the MCP filesystem server
API_TO_TOOL = {
    "/fs/allowed-roots": "list_allowed_directories", # List allowed directories
    "/fs/info":          "get_file_info",           # Get file/directory metadata
    "/fs/read":          "read_text_file",          # Read text file content (mode=media → read_media_file via runtime switch)
    "/fs/list":          "list_directory",          # List directory contents (optional)
    "/fs/search":        "search_files",            # Search files by content (optional)
    "/fs/move":          "move_file",               # Move/rename files/directories (optional)
    "/fs/edit":          "edit_file",               # Edit text files (optional)
    "/fs/write":         "write_file",              # Write content to files (optional)
    "/fs/create-directory": "create_directory",     # Create directories (optional)
}

# Global list of directories the server allows access to
# This will be populated dynamically when connecting to the MCP server
ALLOWED_ROOTS: List[str] = []  # hydrated from MCP on connect


# ========= SMALL HELPERS =========
def build_api_response(api_path: str, tool_payload: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert MCP tool result (already JSON-ified in `tool_payload`) into the
    shape your OpenAPI declares for that endpoint.
    
    Args:
        api_path: The original REST API path that was called
        tool_payload: The result from the MCP tool invocation, already converted to a dict
        args: The original arguments passed to the API call
        
    Returns:
        A properly structured response object matching the OpenAPI schema
    """
    key = normalize_api_path(api_path)
    content = tool_payload.get("content", [])
    err = tool_payload.get("error")

    # Errors: return a small JSON object so Bedrock accepts it and the agent can recover.
    if err:
        return {"error": str(err)}

    # /fs/allowed-roots -> { "roots": ["/abs/path", ...] }
    if key == "/fs/allowed-roots":
        roots: List[str] = []
        for block in content:
            txt = block.get("text") if isinstance(block, dict) else None
            if isinstance(txt, str):
                for line in txt.splitlines():
                    line = line.strip()
                    if line.startswith("/"):
                        roots.append(line)
        return {"roots": roots}

    # /fs/info -> simple metadata dict (schema is loose)
    if key == "/fs/info":
        info: Dict[str, Any] = {"path": args.get("path")}
        for block in content:
            txt = block.get("text") if isinstance(block, dict) else None
            if isinstance(txt, str):
                for line in txt.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        info[k.strip()] = v.strip()
        if "size" in info:
            try: info["size"] = int(info["size"])
            except Exception: pass
        return info

    # /fs/read -> { path, encoding, content }
    if key == "/fs/read":
        out: Dict[str, Any] = {"path": args.get("path")}
        texts = [b.get("text") for b in content if isinstance(b, dict) and isinstance(b.get("text"), str)]
        if texts:
            out["encoding"] = "utf-8"
            out["content"]  = texts[0]
        else:
            out["encoding"] = "base64"
            out["content"]  = ""  # fill if your server returns base64 JSON blocks
        return out

    # default: return payload as-is for loose endpoints
    return tool_payload


def normalize_api_path(p: str) -> str:
    """
    Normalize API paths for consistent lookup.
    Handles URLs, query parameters, fragments, and trailing slashes.
    
    Args:
        p: The API path to normalize
        
    Returns:
        Normalized path string in lowercase
    """
    p = (p or "").strip()
    u = urlparse(p)
    if u.scheme and u.netloc:
        p = u.path or p
    p = p.split("?", 1)[0].split("#", 1)[0]
    if p.endswith("/") and p != "/":
        p = p[:-1]
    return p.lower()

def op_id_for(api_path: str, fallback_tool: str) -> str:
    """
    Get the operation ID for an API path with fallback.
    
    Args:
        api_path: The API path to look up
        fallback_tool: Fallback value if path isn't found
        
    Returns:
        The operation ID or fallback value
    """
    return PATH_TO_OPERATION_ID.get(normalize_api_path(api_path), fallback_tool)

def _coerce_scalar(v: Any) -> Any:
    """
    Convert string values to appropriate types (bool, int, float) when possible.
    Handles common string representations like 'true'/'false' for booleans.
    
    Args:
        v: The value to coerce
        
    Returns:
        Coerced value with appropriate type
    """
    if isinstance(v, str):
        s = v.strip(); ls = s.lower()
        if ls in ("true", "false"): return (ls == "true")
        if ls.isdigit():            return int(s)
        try:
            return float(s) if any(c in s for c in ".eE") else s
        except Exception:
            return s
    return v

def to_jsonable(obj: Any) -> Any:
    """
    Recursively convert objects to JSON-compatible types.
    Handles Pydantic models, dicts, lists, bytes, and custom objects.
    
    Args:
        obj: The object to convert
        
    Returns:
        JSON-compatible representation of the object
    """
    if hasattr(obj, "model_dump"):
        return to_jsonable(obj.model_dump())
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if hasattr(obj, "type") and hasattr(obj, "text"):
        return {"type": getattr(obj, "type"), "text": getattr(obj, "text")}
    return obj

def make_bedrock_agent_runtime():
    """
    Initialize the AWS Bedrock agent runtime client.
    Uses the configured AWS profile and region, with retry settings.
    
    Returns:
        Configured boto3 bedrock-agent-runtime client
    """
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    who = session.client("sts").get_caller_identity()
    print(f"Using profile={AWS_PROFILE} | Account={who['Account']} | ARN={who['Arn']} | Region={AWS_REGION}")
    return session.client("bedrock-agent-runtime", config=Config(retries={"max_attempts": 10, "mode": "standard"}))



# ========= MCP WIRING =========
async def hydrate_allowed_roots(session: ClientSession) -> None:
    """Fill ALLOWED_ROOTS once; ignore header line."""
    global ALLOWED_ROOTS
    try:
        res = await session.call_tool(name="list_allowed_directories", arguments={})
        roots: List[str] = []
        for block in (res.content or []):
            txt = getattr(block, "text", None)
            if isinstance(txt, str):
                for line in txt.splitlines():
                    line = line.strip()
                    if line.startswith("/"):
                        roots.append(line)
        if roots:
            ALLOWED_ROOTS = roots
            print("[DEBUG] ALLOWED_ROOTS:", ALLOWED_ROOTS)
    except Exception as e:
        print("[WARN] allowed-roots hydration failed:", e)

def normalize_args_for_tool(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize arguments for MCP tool calls:
    - Map various parameter names to standard ones (dir/directory/file → path)
    - Coerce string values to appropriate types (boolean, numbers)
    - Handle special cases like read_text_file with mode=media
    
    Args:
        tool: The MCP tool name
        args: Original arguments from the API call
        
    Returns:
        Normalized arguments dictionary, possibly with __switch_tool__ instruction
    """
    alias = {
        "dir": "path", "directory": "path", "root": "path",
        "file": "path", "filepath": "path", "filename": "path",
        "from": "src", "source": "src", "to": "dest", "destination": "dest",
    }
    out: Dict[str, Any] = {}
    for k, v in args.items():
        k2 = alias.get(k, k)
        out[k2] = _coerce_scalar(v if not isinstance(v, list) else [_coerce_scalar(x) for x in v])

    # ensure 'path' when a path-like alias was used
    if "path" not in out:
        for alt in ("dir", "directory", "root", "file", "filepath", "filename"):
            if alt in args:
                out["path"] = _coerce_scalar(args[alt]); break

    # tool-specific polish
    if tool == "read_text_file":
        # allow /fs/read?mode=media to pivot to media tool
        if str(out.get("mode", "text")).lower() == "media":
            out["__switch_tool__"] = "read_media_file"
            out.pop("head", None); out.pop("tail", None)

    return out

def build_api_response(api_path: str, tool_payload: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert MCP tool result (already JSON-ified in `tool_payload`) into the
    response object your OpenAPI declares for that endpoint.
    """
    key = normalize_api_path(api_path)
    content = tool_payload.get("content", [])
    err = tool_payload.get("error")

    # Errors: return as a small JSON object; Bedrock accepts it and can recover.
    if err:
        return {"error": str(err)}

    # /fs/allowed-roots -> { "roots": ["/abs/path", ...] }
    if key == "/fs/allowed-roots":
        roots: List[str] = []
        for block in content:
            txt = block.get("text") if isinstance(block, dict) else None
            if isinstance(txt, str):
                for line in txt.splitlines():
                    line = line.strip()
                    if line.startswith("/"):
                        roots.append(line)
        return {"roots": roots}

    # /fs/info -> a simple metadata dict
    if key == "/fs/info":
        info: Dict[str, Any] = {"path": args.get("path")}
        for block in content:
            txt = block.get("text") if isinstance(block, dict) else None
            if isinstance(txt, str):
                for line in txt.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        info[k.strip()] = v.strip()
        # normalize size if present
        if "size" in info:
            try: info["size"] = int(info["size"])
            except Exception: pass
        return info

    # /fs/read -> { path, encoding, content }
    if key == "/fs/read":
        out: Dict[str, Any] = {"path": args.get("path")}
        texts = [b.get("text") for b in content if isinstance(b, dict) and isinstance(b.get("text"), str)]
        if texts:
            out["encoding"] = "utf-8"
            out["content"] = texts[0]
        else:
            out["encoding"] = "base64"
            out["content"] = ""  # populate if your server returns base64 in a JSON block
        return out

    # default: return tool payload as-is (works for loose schemas)
    return tool_payload


# ========= RETURN-CONTROL HANDLER =========
async def handle_return_control(
    # Handle the returnControl event from Bedrock agent
    # This is where tool calls from the Bedrock agent are processed
    # and results are sent back to continue the conversation
    rt,                           # Bedrock agent runtime client
    agent_id: str,               # ID of the Bedrock agent
    agent_alias: str,            # Alias ID of the Bedrock agent
    session_id: str,             # Current session ID
    rc: Dict[str, Any],          # Return control event data
    mcp_session: ClientSession,  # Active MCP session
    available_tool_names: List[str],  # Names of available MCP tools
) -> None:
    """
    Process returnControl events from the Bedrock agent.
    
    This function is the core bridge between Bedrock and MCP:
    1. Extract API calls from the returnControl event
    2. Map each API call to the appropriate MCP tool
    3. Call the MCP tool with normalized arguments
    4. Format the result according to OpenAPI schema
    5. Send results back to Bedrock to continue the conversation
    
    Args:
        rt: Bedrock agent runtime client
        agent_id: ID of the Bedrock agent
        agent_alias: Alias ID of the Bedrock agent
        session_id: Current session ID
        rc: Return control event data
        mcp_session: Active MCP session
        available_tool_names: List of available MCP tool names
    """

    invocations = rc.get("invocationInputs", []) or []
    return_results: List[Dict[str, Any]] = []   # <-- the only list we build & send

    for inv in invocations:
        api = inv.get("apiInvocationInput") or {}
        action_group = api.get("actionGroup", "") or "filesystem"
        api_path = api.get("apiPath", "")
        key = normalize_api_path(api_path)

        # ---- collect args from parameters and request body ----
        args: Dict[str, Any] = {}
        for p in (api.get("parameters") or []):
            nm = p.get("name"); val = p.get("value")
            if nm: args[nm] = val

        rb = api.get("requestBody") or {}
        content = rb.get("content") or {}
        appjson = content.get("application/json")
        if isinstance(appjson, dict):
            props = appjson.get("properties")
            if isinstance(props, list):
                for prop in props:
                    nm = prop.get("name"); val = prop.get("value")
                    if nm: args[nm] = val
            body_val = appjson.get("body")
            if body_val is not None:
                try:
                    data = json.loads(body_val) if isinstance(body_val, str) else body_val
                    if isinstance(data, dict): args.update(data)
                except Exception:
                    pass

        # ---- map the API path to corresponding MCP tool ----
        # Primary paths we support: /fs/allowed-roots, /fs/info, /fs/read
        tool = API_TO_TOOL.get(key)
        if not tool:
            last = key.rsplit("/", 1)[-1]
            tool = {"info": "get_file_info", "read": "read_text_file"}.get(last)

        # Infer HTTP method if not provided, based on API path
        http_method = (api.get("httpMethod") or
                       ("GET" if key in {"/fs/allowed-roots", "/fs/info", "/fs/list", "/fs/read", "/fs/search"} else "POST")).upper()

        if not tool or tool not in available_tool_names:
            print(f"[WARN] No matching MCP tool for apiPath='{api_path}' (normalized '{key}')")
            return_results.append({
                "apiResult": {
                    "actionGroup": action_group,
                    "apiPath": key,
                    "httpMethod": http_method,
                    "httpStatusCode": 200,
                    "responseBody": {
                        "application/json": {
                            "body": json.dumps({"error": "No matching tool"}, ensure_ascii=False)
                        }
                    }
                }
            })

            continue

        # ---- normalize arguments and handle special tool switches ----
        # For example, /fs/read?mode=media switches from read_text_file to read_media_file
        norm = normalize_args_for_tool(tool, args)
        tool = norm.pop("__switch_tool__", tool)

        # ---- call the MCP tool and process the result ----
        # Always create a valid payload even on error for robust operation
        try:
            print(f"[MCP] Calling {tool} with args={norm}")
            mcp_res = await mcp_session.call_tool(name=tool, arguments=norm)
            tool_payload = {"tool": tool, "content": to_jsonable(mcp_res.content)}
        except Exception as e:
            print("[MCP error]", e)
            tool_payload = {"tool": tool, "error": str(e)}

        # ---- format the response according to OpenAPI schema ----
        body_obj = build_api_response(api_path, tool_payload, norm)

        return_results.append({
            "apiResult": {
                "actionGroup": action_group,
                "apiPath": key,
                "httpMethod": http_method,
                "httpStatusCode": 200,
                "responseBody": {
                    "application/json": {
                        "body": json.dumps(body_obj, ensure_ascii=False)
                    }
                }
            }
        })


    # (optional) debug print to verify shape
    # print("[DEBUG] returnControl payload:",
    #       json.dumps({"invocationId": rc.get("invocationId"),
    #                   "returnControlInvocationResults": return_results}, indent=2))

    # ---- send results back to Bedrock agent and continue the conversation ----
    # This sends the tool results back as sessionState and resumes the agent's processing
    follow = rt.invoke_agent(
        agentId=agent_id,
        agentAliasId=agent_alias,
        sessionId=session_id,
        sessionState={
            "invocationId": rc.get("invocationId"),
            "returnControlInvocationResults": return_results
        },
        endSession=False,
        enableTrace=True
    )

    for ev in follow["completion"]:
        if "chunk" in ev and "bytes" in ev["chunk"]:
            sys.stdout.write(ev["chunk"]["bytes"].decode("utf-8", errors="replace"))
            sys.stdout.flush()
        if "returnControl" in ev:
            await handle_return_control(rt, agent_id, agent_alias, session_id,
                                        ev["returnControl"], mcp_session, available_tool_names)

# ========= MAIN CHAT LOOP =========
async def run_chat(agent_id: str, agent_alias: str):
    """
    Main chat loop that:
    1. Starts the MCP filesystem server
    2. Establishes connection with Bedrock agent
    3. Handles user input and agent responses
    4. Processes tool calls via returnControl events
    
    Args:
        agent_id: The Bedrock agent ID
        agent_alias: The Bedrock agent alias ID
    """
    # Configure and start the MCP filesystem server using npx
    npx_cmd = os.environ.get("NPX_CMD", "npx")  # Allow custom NPX command
    server = SimpleNamespace(
        command=npx_cmd,  # Command to run (npx)
        args=["-y", "@modelcontextprotocol/server-filesystem", *FILESYSTEM_DIRS],  # Server + directories to expose
        env=os.environ.copy(),  # Pass current environment variables
        cwd=None,  # Run in current directory
        encoding="utf-8",  # Use UTF-8 for text encoding
        encoding_error_handler="replace",  # Replace invalid UTF-8 sequences
    )

    # Start the MCP server as a child process and connect to it via stdio
    async with stdio_client(server) as (read_stream, write_stream):
        # Establish MCP client session with the server
        async with ClientSession(read_stream, write_stream) as mcp_session:
            tools = await mcp_session.list_tools()
            available_tool_names = [t.name for t in tools.tools]
            print("MCP tools:", available_tool_names)
            await hydrate_allowed_roots(mcp_session)

            # Initialize Bedrock agent runtime client
            rt = make_bedrock_agent_runtime()
            
            # Create unique session ID based on process ID
            session_id = f"session-{os.getpid()}"

            print("\nType a prompt (or 'quit'):")
            # Get event loop for handling user input asynchronously
            loop = asyncio.get_event_loop()

            # Main input loop
            while True:
                # Read user input asynchronously
                msg = await loop.run_in_executor(None, sys.stdin.readline)
                if not msg: break  # Handle EOF
                
                user_text = msg.strip()
                if user_text.lower() in {"quit", "exit"}: break  # Exit commands

                print("Invoking Bedrock Agent…")
                resp = rt.invoke_agent(
                    agentId=agent_id,
                    agentAliasId=agent_alias,
                    sessionId=session_id,
                    inputText=user_text,
                    enableTrace=True,
                    endSession=False,
                )

                for event in resp["completion"]:
                    if "chunk" in event and "bytes" in event["chunk"]:
                        sys.stdout.write(event["chunk"]["bytes"].decode("utf-8", errors="replace"))
                        sys.stdout.flush()
                    if "returnControl" in event:
                        await handle_return_control(rt, agent_id, agent_alias, session_id,
                                                    event["returnControl"], mcp_session, available_tool_names)
                print()


# ========= ENTRY POINT =========
if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) < 3:
        print("Usage: python client.py <AGENT_ID> <AGENT_ALIAS_ID>")
        sys.exit(2)

    # Set default AWS environment variables if not already set
    os.environ.setdefault("AWS_REGION", AWS_REGION)
    os.environ.setdefault("AWS_PROFILE", AWS_PROFILE)

    asyncio.run(run_chat(sys.argv[1], sys.argv[2]))
