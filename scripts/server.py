#!/usr/bin/env python3
# Copyright 2025 Cisco Systems, Inc. and its affiliates
# 
# SPDX-License-Identifier: Apache-2.0 
"""
Cisco Nexus Dashboard 4.2.1 – Data-Driven MCP Server
=====================================================
Transport : Streamable HTTP (default :8005/mcp) or stdio
Tools     : Named tools dynamically registered from nd_4.2.1_urls_shortlisted.json
            + nd_test_connection         (connectivity check)
            + nd_api_request             (generic passthrough for all ND 4.2.1 APIs)
            + nd_get_operations_summary  (list registered tools by group)

VS Code mcp.json (HTTP – recommended):
    "nd-4.2.1-mcp": { "type": "http", "url": "http://localhost:8005/mcp" }

VS Code mcp.json (stdio):
    "nd-4.2.1-mcp": {
        "type": "stdio",
        "command": "python3",
        "args": ["/path/to/nd_4_2_1_server.py"]
    }

Set MCP_TRANSPORT=stdio in .env to switch transport mode.
"""

import os
import sys
import json
import inspect
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
load_dotenv()

ND_URL     = os.getenv("NDFC_URL", "https://nd.example.com").rstrip("/")
USERNAME   = os.getenv("USERNAME", "admin")
PASSWORD   = os.getenv("PASSWORD", "password")
URLS_PATH  = os.getenv("URLS_PATH", "nd_4.2.1_urls_shortlisted.json")
TRANSPORT  = os.getenv("MCP_TRANSPORT", "streamable-http")   # "streamable-http" | "stdio"
HOST       = os.getenv("MCP_HOST", "0.0.0.0")
PORT       = int(os.getenv("MCP_PORT", "8005"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s  %(name)-18s  %(levelname)-7s  %(message)s",
)
logger = logging.getLogger("ND421")

if not all([ND_URL, USERNAME, PASSWORD]):
    logger.error("Missing NDFC_URL / USERNAME / PASSWORD – check .env")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────
# Module base-path routing
# ──────────────────────────────────────────────────────────────
MODULE_PATHS: Dict[str, str] = {
    "analyze":        "/api/v1/analyze",
    "infrastructure": "/api/v1/infra",
    "manage":         "/api/v1/manage",
    "oneManage":      "/api/v1/oneManage",
    "orchestration":  "/mso",
}

# Tool-name prefix → module key
_PREFIX_TO_MODULE: Dict[str, str] = {
    "nd_infra_":   "infrastructure",
    "nd_manage_":  "manage",
    "nd_analyze_": "analyze",
    "nd_one_":     "oneManage",
    "nd_orch_":    "orchestration",
}


def _module_for_tool(tool_name: str) -> str:
    """Derive the ND module from the tool name prefix."""
    for prefix, module in _PREFIX_TO_MODULE.items():
        if tool_name.startswith(prefix):
            return module
    return "infrastructure"


# ──────────────────────────────────────────────────────────────
# ND HTTP Client
# ──────────────────────────────────────────────────────────────
class NDClient:
    """Async client for Nexus Dashboard 4.2.1 with JWT auth and auto-retry."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self._session: Optional[httpx.AsyncClient] = None

    async def _get_session(self) -> httpx.AsyncClient:
        if self._session is None:
            self._session = httpx.AsyncClient(
                verify=False,
                timeout=float(os.getenv("HTTP_TIMEOUT", "30")),
                headers={"Content-Type": "application/json"},
            )
        return self._session

    async def authenticate(self) -> str:
        """POST /login → JWT token."""
        session = await self._get_session()
        resp = await session.post(
            f"{self.base_url}/login",
            json={
                "userName": self.username,
                "userPasswd": self.password,
                "domain": "DefaultAuth",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.token = data.get("token") or data.get("jwttoken")
        if not self.token:
            raise RuntimeError("No token received from ND login response")
        logger.info("Authenticated with ND 4.2.1 cluster")
        return self.token

    async def _auth_headers(self) -> Dict[str, str]:
        if not self.token:
            await self.authenticate()
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def request(
        self,
        method: str,
        module: str,
        path: str,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Make an authenticated request:  ND_URL + module_base_path + endpoint_path."""
        session = await self._get_session()
        base = MODULE_PATHS.get(module, "")
        url = f"{self.base_url}{base}{path}"
        headers = await self._auth_headers()

        resp = await session.request(
            method.upper(), url, headers=headers, params=params, json=json_body,
        )

        # Auto re-auth on 401
        if resp.status_code == 401:
            logger.info("Token expired – re-authenticating")
            self.token = None
            headers = await self._auth_headers()
            resp = await session.request(
                method.upper(), url, headers=headers, params=params, json=json_body,
            )

        resp.raise_for_status()

        try:
            return resp.json()
        except Exception:
            return {"status": "success", "status_code": resp.status_code}

    async def close(self):
        if self._session:
            await self._session.aclose()


# Global client
nd_client = NDClient(ND_URL, USERNAME, PASSWORD)


# ──────────────────────────────────────────────────────────────
# FastMCP instance
# ──────────────────────────────────────────────────────────────
mcp = FastMCP("Nexus Dashboard 4.2.1 MCP Server")


# ──────────────────────────────────────────────────────────────
# Special tools (hand-coded)
# ──────────────────────────────────────────────────────────────
@mcp.tool()
async def nd_test_connection() -> Dict[str, Any]:
    """Test connectivity and authentication with the Nexus Dashboard 4.2.1 cluster.
    Returns connection status, server URL, and authentication result."""
    try:
        await nd_client.authenticate()
        return {
            "status": "success",
            "message": "Successfully connected to Nexus Dashboard 4.2.1",
            "server_url": ND_URL,
            "authenticated": True,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to connect: {e}",
            "server_url": ND_URL,
            "authenticated": False,
        }


@mcp.tool()
async def nd_api_request(
    module: str,
    method: str,
    path: str,
    query_params: Optional[dict] = None,
    body: Optional[dict] = None,
) -> Dict[str, Any]:
    """Generic API request to any Nexus Dashboard 4.2.1 endpoint.
    Use this for endpoints not covered by the named tools.

    module       – analyze | infrastructure | manage | oneManage | orchestration
    method       – GET | POST | PUT | DELETE | PATCH
    path         – API path relative to module base (e.g. /fabrics/{name}/switches)
    query_params – optional dict of query-string parameters
    body         – optional request body for POST/PUT/PATCH
    """
    if module not in MODULE_PATHS:
        return {"error": f"Unknown module '{module}'. Valid: {', '.join(MODULE_PATHS)}"}
    try:
        return await nd_client.request(method, module, path, params=query_params, json_body=body)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def nd_get_operations_summary() -> Dict[str, Any]:
    """List all registered Nexus Dashboard 4.2.1 MCP tools grouped by category."""
    groups = {}
    for g in _api_config.get("api_groups", []):
        groups[g["Group"]] = [ep["Name"] for ep in g["Endpoints"]]
    return {
        "total_named_tools": _api_config["metadata"]["total_named_tools"],
        "transport": TRANSPORT,
        "endpoint": f"http://{HOST}:{PORT}/mcp" if TRANSPORT != "stdio" else "stdio",
        "nd_url": ND_URL,
        "groups": groups,
        "special_tools": ["nd_test_connection", "nd_api_request", "nd_get_operations_summary"],
    }


# ──────────────────────────────────────────────────────────────
# Dynamic tool registration
# ──────────────────────────────────────────────────────────────
def _make_tool_fn(
    url_tpl: str,
    path_params: List[str],
    http_method: str,
    module: str,
    description: str,
):
    """Factory: returns an async function with proper inspect.Signature
    so FastMCP can expose the right parameters to clients."""

    sig_params = [
        inspect.Parameter(p, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str)
        for p in path_params
    ]
    sig_params.append(
        inspect.Parameter(
            "query_params",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=None,
            annotation=Optional[dict],
        )
    )
    sig = inspect.Signature(sig_params, return_annotation=Dict[str, Any])

    async def fn(**kwargs):
        url = url_tpl
        for p in path_params:
            url = url.replace(f"{{{p}}}", str(kwargs[p]))
        qp = kwargs.get("query_params")
        try:
            return await nd_client.request(http_method, module, url, params=qp)
        except Exception as e:
            return {"error": str(e)}

    fn.__doc__ = description
    fn.__signature__ = sig
    fn.__annotations__ = {p: str for p in path_params}
    fn.__annotations__["query_params"] = Optional[dict]
    fn.__annotations__["return"] = Dict[str, Any]

    return fn


def _register_all_endpoints(config: dict) -> int:
    """Walk the shortlisted JSON and register every endpoint as a named MCP tool."""
    count = 0
    for group in config.get("api_groups", []):
        for ep in group["Endpoints"]:
            name        = ep["Name"]
            url         = ep["URL"]
            method      = ep.get("Method", "GET")
            module      = _module_for_tool(name)
            path_params = ep.get("PathParameters", [])
            qp_list     = ep.get("QueryParameters", [])

            desc = ep.get("Description") or ep.get("Summary", name)
            if qp_list:
                desc += f"\n\nSupported query parameters: {', '.join(qp_list)}"

            fn = _make_tool_fn(url, path_params, method, module, desc)
            fn.__name__ = name
            fn.__qualname__ = name

            mcp.tool(name=name)(fn)
            count += 1
            logger.debug(f"  Registered: {name}  [{method}] {module}{url}")

    return count


# ──────────────────────────────────────────────────────────────
# Bootstrap – runs at import time so `mcp` is ready for any transport
# ──────────────────────────────────────────────────────────────
_urls_file = Path(__file__).parent / URLS_PATH
if not _urls_file.exists():
    logger.error(f"URLs file not found: {_urls_file}")
    sys.exit(1)

with open(_urls_file) as f:
    _api_config = json.load(f)

_tool_count = _register_all_endpoints(_api_config)
logger.info(
    f"Registered {_tool_count} named tools + 3 special tools "
    f"({_tool_count + 3} total) from {URLS_PATH}"
)


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Nexus Dashboard 4.2.1 MCP Server")
    logger.info(f"  ND cluster  : {ND_URL}")
    logger.info(f"  Username    : {USERNAME}")
    logger.info(f"  Transport   : {TRANSPORT}")

    if TRANSPORT == "stdio":
        logger.info("  Mode        : stdio (VS Code managed)")
        mcp.run()
    else:
        logger.info(f"  Endpoint    : http://{HOST}:{PORT}/mcp")
        logger.info("=" * 60)
        mcp.run(transport=TRANSPORT, host=HOST, port=PORT)
