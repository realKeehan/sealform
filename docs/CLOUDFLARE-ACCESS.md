# Putting the dashboard behind Cloudflare Access (Google sign-in)

Cloudflare Access puts a login in front of the dashboard at Cloudflare's edge. People sign in with
Google (or any provider you enable), and Cloudflare forwards each request with a signed token. sealform
checks that token itself, so someone who reaches your server directly cannot skip the login. The
Google address must also belong to a dashboard account, so a loose Access rule cannot let a stranger in.

With Access on, the dashboard's own password and authenticator-app sign-in are not used.

> **What was and was not tested.** The token checks are tested against a local stand-in that signs
> tokens the way Cloudflare does (forged signatures, `alg: none`, wrong audience, expired and more are
> all refused). They have **not** been run against a real Access application. The Cloudflare dashboard
> menus below are written from memory of how they are laid out and may be named differently now; if a
> step does not match, follow Cloudflare's current Zero Trust documentation for the same goal.

## What you need

- The domain's DNS on Cloudflare, with the hostname that serves the dashboard **proxied** (orange cloud).
  Access only protects traffic that goes through Cloudflare.
- A Cloudflare Zero Trust team (the free plan covers small teams; check current limits).
- A Google Cloud OAuth client (free) so Access can offer "Sign in with Google".

## Steps

1. **Pick your team domain.** In Zero Trust, the team name gives you `<team>.cloudflareaccess.com`.
2. **Add Google as a login method.** In Google Cloud, create an OAuth client of type Web application. Set
   its authorized redirect URI to `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`. In Zero
   Trust, add Google under the authentication login methods and paste the client ID and secret.
3. **Create a self-hosted Access application** for the dashboard path only, for example
   `example.com/_sf`. Add an Allow policy that includes the email addresses of the people who should
   get in, and limit it to the Google login method. Do **not** cover `/sealform/api/*` or
   `/.well-known/sealform-keys.json`: signers and verifiers must reach those without logging in.
4. **Copy the application's Audience (AUD) tag** from its overview page.
5. **Configure sealform:**

   ```js
   const sealform = await createSealform({
     /* ... */
     adminPath: '/_sf',
     adminAccess: {
       teamDomain: 'your-team.cloudflareaccess.com',
       audience: 'the AUD tag from step 4',
     },
     clientIp: 'cf-connecting-ip', // the real visitor address, set by Cloudflare
   });
   ```

6. **Create dashboard accounts with the same email as each Google account:**

   ```bash
   npx sealform admin create --data /path/to/data --key /path/to/private-key.json \
     --email you@example.com --name "Your Name" --role owner
   ```

   The temporary password it prints is not used while Access is on. Roles still apply.

## Check it works

1. Open the dashboard in a private window. You should land on Cloudflare's login, then Google, then the
   dashboard overview, with no password prompt.
2. Request the dashboard path directly from your server's address, skipping Cloudflare. You should get a
   403 page saying it is only reachable through Cloudflare Access.
3. Sign in with a Google account that has no dashboard account. You should get a 403 naming the address.
4. Click "Sign out". It should end the Cloudflare session too, not drop you back in.

## How it protects you

- Every dashboard request must carry a valid Access token: RS256 signature checked against your team's
  published keys, your team as issuer, your application as audience, not expired, with an email.
- The dashboard session belongs to the email in the token. A cookie from one person is not accepted
  with a token for another.
- Disabling an account in the dashboard blocks it immediately, even while its Access session is valid.
- Cloudflare's keys are cached for an hour. An unknown key id triggers at most one refetch a minute.

## If you ever leave Cloudflare

Remove `adminAccess` and sign-in goes back to password plus authenticator app. Accounts created while
Access was on only have the unused temporary password, so use `sealform admin create` for a fresh owner,
or the Accounts page "Reset password and two-factor", before you switch.
