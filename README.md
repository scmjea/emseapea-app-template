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

## Where the person's token comes from — two routes, both already built

The token is an OAuth access token issued by the emseapea control plane's own
sign-in — the same kind an MCP client carries — and the control plane rejects
it if the person's organization is not the one this app's handle belongs to.
So a borrowed token from another org buys nothing.

There are two ways this app gets one, and **both are wired up**:

1. **Relayed.** An agent or MCP client that has signed in to emseapea sends its
   token to this app as `X-Emseapea-Person`. Nothing more to build — this app
   forwards it.
2. **Signed in here.** Send the person to **`/auth/emseapea/sign-in`**. This app
   discovers emseapea's OAuth endpoints, runs authorization-code + PKCE, shows
   them emseapea's consent screen, and keeps the resulting token in an HttpOnly
   cookie for their session. This is the route a person opening the app in a
   browser needs.

Route 2 needs two variables, and **emseapea sets both when it deploys you**:

```
EMSEAPEA_URL        where the control plane lives
EMSEAPEA_CLIENT_ID  this app's own OAuth client id
```

**There is no client secret, on purpose.** Emseapea registers this app as a
*public* OAuth client and PKCE is its proof of identity, so there is nothing
here that leaking would cost you. Emseapea also registers exactly **one**
permitted redirect — `/auth/emseapea/callback` on this app's own origin — so an
authorization code cannot be sent anywhere else, even by a caller who asks.

If you change `CALLBACK_PATH` in `src/index.js`, the flow stops working with
`Invalid redirect URI`: emseapea registered the old path and will not send a
code to a new one.

This app still **cannot mint a token**, and neither can you. With neither route
satisfied, `/me/google-files` refuses: a browser is sent to sign in, and a
script gets a 401. It never falls back to calling as nobody in particular, and
neither should anything you add.

## This applies to repositories created from here on

A repository generated from this template gets a copy of these files; it does
not track them. Changes made here do not reach a repo that already exists — if
this app was created before this section appeared, `src/index.js` will have
neither the sign-in routes nor the `X-Emseapea-Person` relay, and you will need
to add them by hand.
