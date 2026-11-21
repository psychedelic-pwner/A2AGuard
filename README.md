# a2aguard

Local conformance checks for Agent-to-Agent (A2A) HTTP servers. Each check is one assertion. It reports pass or fail with the evidence and a fix.

## What A2A is

A2A is a way for one software agent to find another and hand it work over HTTP. The callee publishes an agent card at `/.well-known/agent-card.json`: who it is, which skills it offers, and how the caller authenticates. The caller then opens a task, may attach artifacts (documents or text the agent should treat as data), and may register a callback URL for when the task finishes.

A call is a small HTTP conversation, not a shared memory. The caller holds a bearer token. The body is a message plus an optional skill name and artifacts. The server stores the task, returns an id, and later lets that same caller read it. a2aguard speaks that profile: card, `POST /tasks`, `GET /tasks/{id}`, `POST /tasks/{id}/callback`, and `POST /skills/{id}`.

Agent-to-agent hygiene matters because the caller is another program, and the server will act on what it accepts. A missing owner check lets a second token read the first token's task. An open create route grows a queue without a cap. A callback aimed at a link-local or metadata address is an outbound request waiting to happen. An artifact copied into a system-instruction field is data promoted into control. These are properties of the HTTP surface. They are visible before anyone argues about what the model meant.

## Check catalogue

Failure lines below are the evidence column from `a2aguard run` against the vulnerable lab (`a2aguard lab --vulnerable`).

### `card_hygiene`

Asserts the agent card is reachable, declares auth, and does not leak internal hosts or combine wildcard CORS with credentials.

```
card_hygiene                FAIL    high      neither HTTPS nor an explicit development marker; auth schemes are missing; internal host or port leaked: http://10.0.0.8:5432/internal, http://169.254.169.254/latest/meta-data/, 10.0.0.8, 169.254.169.254; CORS allows any origin with credentials
```

Fix: serve `/.well-known/agent-card.json` over HTTPS or set the card environment to development. Declare `securitySchemes` and `security`. Remove internal hostnames, private addresses, and service ports. Do not send `Access-Control-Allow-Origin: *` together with credentials.

### `auth_required`

Asserts task creation rejects a request that has no `Authorization` header.

```
auth_required               FAIL    high      POST /tasks without credentials returned 200
```

Fix: require `Authorization: Bearer` before creating a task. Respond 401 or 403 and do not store the task.

### `auth_rejects_unknown_token`

Asserts task creation rejects a bearer token the server did not issue.

```
auth_rejects_unknown_token  FAIL    high      unknown bearer returned 200
```

Fix: keep an allowlist of issued tokens. Unknown bearer values get 401 or 403, and no new task.

### `task_isolation`

Asserts one identity cannot read a task that belongs to another identity.

```
task_isolation              FAIL    high      peer read returned 200
```

Fix: bind each task to the authenticated identity. Return 403 or 404 when the caller is not the owner.

### `input_bounds`

Asserts an oversized task body is rejected with 4xx and is not stored.

```
input_bounds                FAIL    medium    oversized payload returned 200
```

Fix: reject task bodies larger than 65536 bytes with 413 before parsing or storing them. Do not answer 5xx.

### `task_bounds`

Asserts a per-identity task cap refuses further creates. The probe sends at most 12 creates on the bounds token.

```
task_bounds                 FAIL    medium    created 12 tasks with no 429 (last status 200)
```

Fix: enforce a per-identity queue cap at or below 12 open tasks and respond 429.

### `callback_allowlist`

Asserts callback registration refuses loopback, private, and link-local URLs. The check submits the URL. It does not request it.

```
callback_allowlist          FAIL    high      private callback accepted: http://127.0.0.1:9/hook -> 200; http://10.0.0.5/hook -> 200; http://192.168.1.5/hook -> 200; http://172.16.0.5/hook -> 200; http://169.254.169.254/latest -> 200; http://[::1]/hook -> 200
```

Fix: allowlist callback URLs. Reject loopback, private, link-local, and metadata addresses with 400. Store an accepted URL only.

### `capability_honesty`

Asserts every skill the card declares is implemented, and an undeclared skill id is rejected.

```
capability_honesty          FAIL    medium    declared skill echo returned 404; undeclared /skills route returned 200; undeclared task skill returned 200
```

Fix: publish only skills the server implements. Reject unknown skill ids with 4xx on both `/skills/{id}` and task creation.

### `artifact_is_data`

Asserts text artifacts are type-checked and stored as data, not copied into an instruction path.

```
artifact_is_data            FAIL    high      artifact text was copied into an instruction field or marked executed; stored artifact is missing a data mimeType or role; missing mimeType returned 200; non-data mimeType returned 200
```

Fix: require a data `mimeType`, store the artifact with `role=data`, and reject a missing or non-data type with 4xx. Do not copy artifact text into a system or instruction field, and do not mark it executed.

`a2aguard checks` prints the same nine names with severity and the one-line assertion.

## Discrimination matrix

`a2aguard selftest` starts the hardened lab and the vulnerable lab on loopback and expects every check to pass on the first and fail on the second. This is the output of `.venv/bin/a2aguard selftest`:

```
check                       hardened  vulnerable
card_hygiene                PASS      FAIL
auth_required               PASS      FAIL
auth_rejects_unknown_token  PASS      FAIL
task_isolation              PASS      FAIL
input_bounds                PASS      FAIL
task_bounds                 PASS      FAIL
callback_allowlist          PASS      FAIL
capability_honesty          PASS      FAIL
artifact_is_data            PASS      FAIL
discrimination: ok
```

## Quickstart

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

That install exposes the `a2aguard` console script at `.venv/bin/a2aguard`.

Vulnerable lab, then the same port hardened. Use two terminals. The lab binds `127.0.0.1` only.

```bash
.venv/bin/a2aguard lab --vulnerable --port 8080
.venv/bin/a2aguard run http://127.0.0.1:8080
```

Stop the lab and start the hardened one. The same `run` should exit 0.

```bash
.venv/bin/a2aguard lab --hardened --port 8080
.venv/bin/a2aguard run http://127.0.0.1:8080
```

`run` exits 0 when every check passes, 1 when a check at or above `--fail-on` fails (default `info`), and 2 on usage errors, an unreachable target, or a refused non-local host. Add `--json` or `--sarif` for a machine-readable report.

The lab accepts three bearer tokens and they are the defaults: `a2aguard-lab-alpha`, `a2aguard-lab-beta`, and `a2aguard-lab-bounds`.

Confirm the matrix without leaving a server up:

```bash
.venv/bin/a2aguard selftest
```

## Your own A2A server

Serve the profile above. Issue two bearer tokens plus a third token the task-cap probe may fill. Loopback needs no extra flag:

```bash
a2aguard run http://127.0.0.1:8080 \
  --token "$TOKEN_A" \
  --peer-token "$TOKEN_B" \
  --bounds-token "$TOKEN_BOUNDS"
```

Any other host is refused. The command prints a warning and exits 2:

```
warning: refusing non-local target http://example.com/agent. Pass --allow-remote only for a host you are authorized to test.
```

`--allow-remote` is the override. It prints a responsible-use notice on stderr, then sends the probes:

```bash
a2aguard run https://agent.example \
  --allow-remote \
  --token "$TOKEN_A" \
  --peer-token "$TOKEN_B" \
  --bounds-token "$TOKEN_BOUNDS"
```

```
warning: responsible-use notice: --allow-remote set; hygiene probes will be sent to agent.example. Use this only on a server you operate or are allowed to test. Checks create and read tasks and submit callback URLs. They do not request those URLs.
```

The task-cap check creates at most 12 tasks with the bounds token. The other checks create a handful of tasks with the primary token.

## Design notes

The runtime imports are the Python standard library only (`http.client`, `ipaddress`, `json`, `argparse`). `pip install -e .` installs no third-party packages. A test walks `src/a2aguard` and fails if a runtime import is outside the stdlib. That keeps the checker small enough to read and free of a client stack that follows redirects on its own.

Each check is an assertion about a status code, a declared field, or who can read a task. The suite does not ship exploit content, does not fuzz for crashes, and does not try to make the agent do anything with a callback. A failure is "this response was 200" or "this field held the artifact text", plus the fix.

Behaviour is bounded. The size probe sends one body just over 64KB. The task-cap probe stops at 12 creates. HTTP uses a 2 second timeout, one extra attempt on transport failure, no redirects, and a 1MB response cap. Callback URLs are submitted in JSON and never fetched.

## Responsible use and limitations

Run this against a server you operate or are allowed to test. The default refuses any host that is not loopback (`127.0.0.1`, `::1`, or `localhost`) and prints the warning above. `--allow-remote` is an explicit override and names the host it will probe. The vulnerable lab is a local discrimination target: it binds loopback, it does not call out, and the checks against it are the same assertions as against a hardened server.

a2aguard covers protocol hygiene for the profile in this document: card contents, authentication of task routes, owner isolation, size and queue caps, callback address class, skill honesty, and artifact storage shape. It does not judge application logic inside a skill, whether a model obeyed an instruction, or anything the server does after it has accepted a well-formed task. A passing run means this HTTP surface matched the assertions. It does not mean the agent is safe.

## Credits

See [CONTRIBUTORS.md](CONTRIBUTORS.md).
