# Short walkthrough

Run `python -m recovery.demo --out evidence`, then open evidence/report.html.

1. **Connect:** authorization code with S256 PKCE; protected sample record is readable.
2. **Renew:** the demo expires the client-side access deadline to exercise renewal. Provider rotation count increases to one.
3. **Lose response:** the fixture deliberately delays its response after rotating. The client times out and records UNKNOWN. Count is now two.
4. **Try again:** the client refuses another refresh. Count stays two.
5. **Reconnect:** an explicit new authorization restores resource access. Count stays two because authorization-code exchange is not counted as token refresh.

Expand each stage for captured journal entries. The HTML is an offline evidence viewer; it does not trigger provider requests when clicked. The included video records this viewer.

Repeat browser checks: `npm ci`, `npx playwright install chromium`, `npm run test:browser`. CI executes these checks on a freshly generated report. Screenshots are written to test-results/browser. Automated axe was additionally run locally and is reported separately from the checked-in browser assertions.
