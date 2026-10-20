# BurpMcpBridge

A Burp Suite extension that connects the active Burp project to Codex through a local MCP server.

## Install

1. Download `BurpMcpBridge.jar` from the [latest release](https://github.com/hackersroot/BurpMcpBridge/releases/latest).
2. In Burp, open **Extensions → Installed → Add**.
3. Choose **Java**, select the downloaded JAR, and load it.
4. Restart Codex after the extension configures the MCP connection.
5. Keep Burp open with the extension loaded while using the MCP tools.

On first load, the extension creates a local authentication token and updates Codex’s configuration. Keep the generated `burp-mcp-bridge.properties` file private; don’t upload or share it.

## Tools

- `burp_proxy_history` — reads captured requests and responses.
- `burp_send_request` — sends a request through Burp; this may change data on the destination server.
- `burp_send_to_repeater` — creates a Repeater tab with a prepared request; it doesn’t send it.
- `burp_send_to_intruder` — creates an Intruder tab with a prepared request; it doesn’t configure payloads or start an attack.

## Limits

The extension supports text-based HTTP/1 requests. Binary bodies and HTTP/2 framing aren’t supported. It doesn’t control Burp Scanner or toggle interception.
