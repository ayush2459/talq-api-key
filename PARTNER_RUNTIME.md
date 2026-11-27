# FlowSense Local Partner Runtime and TALQ Validator

## Scope and status

The runtime is designed to run on the partner's own Windows/macOS/Linux computer.
It stores reports, accepted response bodies and quarantined bodies locally.
It does not upload validation artifacts or credentials to a hosted service.

The validator checks the selected HTTP response against the official TALQ
Gateway OpenAPI 2.7.1 response contract. It is not the TALQ Certification Tool,
does not perform the full semantic/functional test suite, and does not confer
TALQ certification. A response is accepted only when the operation, status,
content type and schema can be validated by the pinned contract.

## Install

Install Python 3.10+ and dependencies:

```bash
python -m pip install cryptography jsonschema openapi-schema-validator
```

On macOS, use `python3` if needed.

Download the official TALQ specification snapshots once while online:

```bash
python talq_validator/fetch_talq_specs.py
```

The script verifies each file against the pinned Git blob ID. Once downloaded,
validation is offline. The files are stored under
`talq_validator/specifications/2.7.1/`.

## Configure the agent

Copy `partner-agent.example.json` to `partner-agent.json` (PowerShell: `Copy-Item partner-agent.example.json partner-agent.json`; macOS/Linux: `cp partner-agent.example.json partner-agent.json`), then set the
partner's private Gateway URL, path to the public server certificate, encrypted
API-key vault path and permitted GET jobs. Never add secrets to this JSON file.
Only configure routes that the partner is authorized to call and that actually
match the TALQ Gateway 2.7.1 specification.

The example `/devices` job is a starting configuration, not a claim that the
current FlowSense response already conforms. Run it and inspect the first
validation report. The custom `/v1/test-data` fixture endpoint is intentionally
not treated as a TALQ operation and cannot receive a TALQ-compliant PASS.

## Run once or continuously

```bash
python partner_runtime/agent.py --once
python partner_runtime/agent.py
python partner_runtime/agent.py --interval 60
```

The agent prompts for both encrypted vault passphrases without echoing them. It reacquires a short-lived OAuth access token on every cycle and polls configured GET jobs (default 300 seconds; minimum 15 seconds). When an API key enters the configured rotation window (default seven days), it requests a replacement, verifies it, atomically stores it in the local encrypted vault, and then retires the old key. It performs read-only GET polling only; mutating TALQ operations remain outside the polling agent.

## Validate a saved response manually

```bash
python talq_validator/validate_response.py --method GET --path /devices --status 200 --content-type application/json --response response.json --report report.json
```

## Local output policy

- Schema-valid response: stored in `partner-agent-data/responses/`.
- Invalid, undocumented or unparseable response: stored in
  `partner-agent-data/quarantine/` with a local JSON report under
  `partner-agent-data/reports/`.
- Never use `curl -k`, disable certificate verification, or commit vaults,
  private keys, onboarding tokens, response dumps or partner data.

## Official TALQ sources

The specification snapshots are from the TALQ Consortium's public
`TALQ-consortium/TALQ_specification` repository, version 2.7.1:
- Gateway API OpenAPI
- CMS API OpenAPI
- TALQ data model OpenAPI

The official certification test tool and certification process are separate
from this local OpenAPI validator and may require TALQ Consortium membership.


## Automated partner onboarding

Run the onboarding client on the partner computer. The RSA private key is generated and encrypted locally; only the public key is submitted.

```bash
python partner_runtime/onboarding.py submit --contact "Partner Contact" --email partner@example.com --organization "Partner Org" --purpose "Read approved gateway data for integration testing" --client-address "partner-lan-host"
python partner_runtime/onboarding.py status
python partner_runtime/onboarding.py claim
```

The FlowSense administrator must review and approve the request and provision the integration. This approval gate is intentionally not automated. After provisioning, the partner checks status and claims the one-time encrypted credentials. The claim command decrypts them locally and saves `partner_oauth_credentials.enc`; it never prints the client secret. The initial API-key issuance is a separate bootstrap action: authenticate to `/oauth/token` with the newly claimed OAuth credentials, call `POST /integrations/me/api-keys`, then save the one-time API key and its `key_id`/`expires_at` metadata in the encrypted API-key vault. The existing `scripts/partner_test_client.py` supports verify and rotate once that vault exists. Do not paste credentials into chat, shell history, or source control.

The runtime now requires both encrypted vaults. Configure `oauth_vault` and `api_key_vault` in `partner-agent.json`. It obtains OAuth access tokens automatically and rotates API keys before expiry. Set `rotate_before_days` to adjust the default seven-day rotation window. If rotation fails, it retains the previous local key and stops that polling cycle rather than retiring a credential it has not verified.
