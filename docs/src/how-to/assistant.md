# Query nanobom from an assistant (MCP)

This guide connects an assistant that speaks the Model Context Protocol (MCP), such as Claude
Code or Claude Desktop, to nanobom's [MCP endpoint](../reference/mcp.md), so you can ask it
about your organization's vulnerabilities in plain words. The assistant reads; it cannot change
anything in nanobom.

## Create a read token

The assistant authenticates with a token, as scripts do. Give it a **read** token: it reads
everything its reach holds and changes nothing ([Tokens and scopes](../explanation/tokens.md)).
A project token limits it to one project.

1. In the organization's **Settings → API tokens**, name the token (`assistant`), choose the
   whole organization or one project, choose **Read only** as scope, and select
   **Create token**.
2. Copy the token: it is shown once.

From the command line, on the server (add `--project web` for one project):

```sh
nanobom token create --organization acme --name assistant --scope read
```

## Connect the assistant

The endpoint is `/mcp` under your instance's public URL, with the token in the
`Authorization` header.

### Claude Code

```sh
claude mcp add --transport http nanobom https://nanobom.example.com/mcp \
  --header "Authorization: Bearer nanobom_…"
```

To share the server with a repository's contributors without sharing the token, add it to the
project's `.mcp.json`, and have each contributor set `NANOBOM_TOKEN` in their environment:

```json
{
  "mcpServers": {
    "nanobom": {
      "type": "http",
      "url": "https://nanobom.example.com/mcp",
      "headers": {"Authorization": "Bearer ${NANOBOM_TOKEN}"}
    }
  }
}
```

### Claude Desktop and clients without HTTP headers

Clients that only start local servers reach the endpoint through
[mcp-remote](https://www.npmjs.com/package/mcp-remote), which needs Node.js. In Claude Desktop,
open **Settings → Developer → Edit Config** and add:

```json
{
  "mcpServers": {
    "nanobom": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://nanobom.example.com/mcp",
        "--header",
        "Authorization:${NANOBOM_AUTHORIZATION}"
      ],
      "env": {"NANOBOM_AUTHORIZATION": "Bearer nanobom_…"}
    }
  }
}
```

Restart Claude Desktop afterwards.

### Other clients

Any client of the Streamable HTTP transport works: give it the URL and the header
`Authorization: Bearer nanobom_…` (or `X-Api-Key: nanobom_…`). In VS Code, for example, in
`.vscode/mcp.json`:

```json
{
  "servers": {
    "nanobom": {
      "type": "http",
      "url": "https://nanobom.example.com/mcp",
      "headers": {"Authorization": "Bearer ${input:nanobom-token}"}
    }
  },
  "inputs": [
    {"id": "nanobom-token", "type": "promptString", "description": "nanobom token", "password": true}
  ]
}
```

## Check the connection

In Claude Code, `/mcp` lists the server and its seven tools. If the client reports an
authentication error, the token is wrong or revoked: the endpoint answers `401` to a request
without a valid token, and does not accept the session of the interface.

## Ask questions

- "Which of my projects are affected by CVE-2021-44228?" (`affected_by`, which also matches the
  GHSA and other aliases of the CVE)
- "What is open and critical in web on release/2.4, and how does it come in?" (`list_findings`,
  then `get_finding` for the dependency paths)
- "Which known exploited vulnerabilities are still open, and which is due first?"
- "Which components use a GPL license?" (`search_components`)
- "Does api 3.1 break our license policy?" (`license_violations`)
- "Which projects have not received an SBOM for a while?" (`list_projects`, `stale`)

The answers link to the findings and projects in the interface, where you triage them.

## Mind the advisory text

Advisories come from OSV and are written by third parties. Someone could write one to steer an
assistant that reads it. nanobom returns that text in clearly marked fields and tells the
assistant to treat it as data, but the defence that holds is on your side:

- give the assistant a read token, so whatever it is told, it cannot change anything in
  nanobom;
- be careful when the same session can act elsewhere (run commands, write files, open pull
  requests), and review what the assistant proposes after reading advisories.

Revoking the token in **Settings → API tokens** disconnects the assistant at once.
