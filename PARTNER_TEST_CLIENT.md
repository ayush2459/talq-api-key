# Cross-platform FlowSense partner test client

This client runs on Windows, macOS, and Linux. It talks only to the restricted
Partner API listener and keeps API keys, OAuth credentials, and access tokens
on the partner machine.

## Prerequisites

- Python 3.10 or newer.
- Install dependencies: `python -m pip install -r requirements.txt`
  (on macOS, use `python3` if that is the installed command).
- Network access to the FlowSense partner listener. A remote home network
  generally needs an approved VPN or other private network route; the
  FlowSense LAN IP is not publicly routable.
- The FlowSense CA/server certificate copied through an approved secure
  channel. Never copy the FlowSense server private key.
- An encrypted `partner_api_key.enc` vault created by the partner credential
  workflow. The `rotate` command also requires
  `partner_oauth_credentials.enc`.

## Retrieve synthetic test data

From the repository root, run:

Windows:
```powershell
python .\scripts\partner_test_client.py --ca-cert C:\FlowSense-Partner\server.crt retrieve
```

macOS/Linux:
```bash
python3 scripts/partner_test_client.py --ca-cert ./server.crt retrieve
```

The client prompts for the API-key vault passphrase without echoing it. It
verifies the API key, calls `GET /v1/test-data`, and prints the response only
if the server identifies the environment as `testing`, the source as
`synthetic_test_fixture`, and every returned device as synthetic.

If the certificate is already trusted by the operating system, omit
`--ca-cert`. Alternatively set `SSL_CERT_FILE` to the certificate path.

## Verify the current API key

```bash
python3 scripts/partner_test_client.py --ca-cert ./server.crt verify
```

Use `python` instead of `python3` on Windows where appropriate.

## Rotate and retire the API key

```bash
python3 scripts/partner_test_client.py --ca-cert ./server.crt rotate
```

The client prompts separately for the API-key vault and OAuth vault
passphrases. It then:

1. Obtains an OAuth access token using the local encrypted OAuth vault.
2. Requests a replacement API key.
3. Verifies the replacement key.
4. Saves the replacement in the encrypted local API-key vault using the
   existing API-key vault passphrase.
5. Retires the previous key only after the replacement is saved and verified.
6. Confirms that the previous key receives HTTP 401 and the replacement still
   authenticates.

If a failure occurs before retirement, the old key is not intentionally
retired. If retirement fails after the replacement is saved, the replacement
remains in the local vault and the old key may remain active; inspect the
server-side key list with an administrator before retrying.

## Important boundaries

- This client does not submit onboarding requests or claim credentials. Use
  `scripts/partner_onboarding_client.py` for those separate steps.
- Do not run the onboarding script with `--help`; it is not an argparse
  command-line utility.
- Never commit `.env`, private keys, onboarding status tokens, encrypted
  credential vaults, decrypted credentials, OAuth tokens, or API keys.
- Do not use `curl -k` or disable TLS certificate verification.
- The isolated `/v1/test-data` endpoint returns synthetic fixtures only.
  This client does not grant facility access and does not access production
  RDS data.
- API-key rotation is a state-changing operation. Run it only when the partner
  intentionally wants to replace the active key.
