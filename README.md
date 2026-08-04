# {{APP_NAME}} — a governed emseapea app

This repository was created from your organization's approved template by the
emseapea provisioning broker. It comes with:

- CI that runs the SAME checks the deploy gate enforces (gitleaks + Semgrep) —
  green here means green at the gate. Semgrep checks the code against a set of
  known insecure patterns; it is not exhaustive and a green check is not a
  guarantee the code is secure — write safe code regardless of what the scan
  finds.
- A credential handle (never a raw secret) delivered via `get_workspace`;
  redeem it through your organization's gateway (`/u/<system>/...`).
- A worked example of an on-behalf-of call — a person reading their own Google
  Drive files — in `src/index.js`, and tests for it in `test/`. Run them with
  `npm test` (Node's own test runner; there are no dependencies to install).

Build whatever the approved intent describes. Every deploy goes through the
emseapea deploy gate.

## Two headers, and they are not interchangeable

```http
GET {GATEWAY_URL}/u/google/drive/v3/files?pageSize=10
Authorization: Bearer {CREDENTIAL_HANDLE}
X-Emseapea-Person: {the signed-in person's emseapea token}
```

`Authorization` says which **app** is calling. It is not a vendor token, it
never reaches the vendor, and it goes to `GATEWAY_URL` — never to the vendor's
own host, whatever the vendor's documentation says.

`X-Emseapea-Person` says which **person** the app is calling for. Systems your
org reaches "only what the person using it can already see" need it: on Google
Workspace it decides whose Drive, mail and directory view come back, so with
nothing forwarded the gateway has nobody to act as and refuses the call rather
than substituting someone. Treat the token as opaque cargo — do not decode,
log, store, or send it anywhere except `GATEWAY_URL`.

## Where the person's token comes from — you have to do one of these

**This template relays a person token that arrives on the inbound request. It
cannot obtain one.** A Worker has no session, and provisioning does not
register this app as a sign-in client anywhere. The token is an OAuth access
token issued by the emseapea control plane's own sign-in — the same kind an
MCP client carries — and the control plane rejects it if the person's
organization is not the one this app's handle belongs to.

So for the header to carry a real person, one of these has to be true:

1. **Your caller already holds one.** An agent or MCP client that has signed in
   to emseapea sends its token to this app as `X-Emseapea-Person`. Nothing more
   to build — this template forwards it.
2. **Your app signs people in to emseapea itself.** Discover the endpoints at
   `<control plane>/.well-known/oauth-authorization-server`, register as a
   client, run the OAuth authorization-code + PKCE flow, and hold the resulting
   token for the signed-in person. **That flow is not in this template**, and
   nothing in emseapea sets it up for a governed app today.

Until one of them is true, `/me/google-files` answers 401. It never falls back
to calling as nobody in particular, and neither should anything you add.

## This applies to repositories created from here on

A repository generated from this template gets a copy of these files; it does
not track them. Changes made here do not reach a repo that already exists —
if this app was created before this section appeared, `src/index.js` will not
send `X-Emseapea-Person` and you will need to add it by hand.
