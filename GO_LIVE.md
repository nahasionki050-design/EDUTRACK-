# EduTrack SMS - go-live checklist

## How the money is protected now
1. **Credit wallet is server-only.** It lives at `schools/{code}/sms/credits`. Browsers can read it,
   never write it. Only the Vercel function changes it (send, refund, top-up).
2. **Sending needs a School SMS PIN.** The admin issues a 6-digit PIN per school (Admin -> SMS Credits ->
   "Issue / Reset PIN"). The server keeps only a salted scrypt hash in `smsMeta/pins/{code}`, a place no
   browser can read, so knowing a school code - or reading the school's synced data - is not enough to send.
   5 wrong PINs lock that school for 30 minutes (attempts are counted atomically, so parallel guessing fails).
3. **Deleting a school** wipes its wallet + PIN on the server. **Changing a school code** moves them.

## Deploy order
1. **Vercel**: replace `api/sendSms.js`, set env vars (below), redeploy.
2. **App**: upload the new `index.html` next to `sms-config.js` (with your real Vercel URL).
3. **Firebase** -> Realtime Database -> Rules -> paste `database.rules.json` -> Publish.

## Environment variables (Production) - redeploy after changing any
- `AT_USERNAME` = LIVE Africa's Talking app username (not `sandbox`), `AT_API_KEY` = the LIVE key
- `AT_SENDER_ID` only once approved, otherwise empty
- `ALLOWED_ORIGINS` = exact app origin, no trailing slash
- `ADMIN_EMAILS` = your cloud admin login email
- `FIREBASE_SERVICE_ACCOUNT` (whole JSON), `FIREBASE_DATABASE_URL`
- `SMS_DAILY_CAP` = 1000 to start
- Top up your Africa's Talking airtime.

## Day-one tasks for each school
1. Admin signs in to **Cloud Admin Account** (needed for PINs, top-ups, delete, change-code).
2. **Issue / Reset PIN** -> the PIN is shown ONCE. Give it to the school's DOS/HOI only.
3. Top up credit. (Balances from before this update were browser-editable and are NOT carried over:
   note old ones from Firebase console `schools/<code>/data/smsCredits` and re-add with "Custom".)
4. The DOS types the PIN once in the SMS tab; it is kept in memory until logout.

## Verify (15 minutes)
1. Rules Playground (authenticated): write `/schools/X/sms/credits` DENIED; read allowed; write `/schools/X/data/name` allowed;
   read `/smsMeta/pins/X` DENIED.
2. Issue a PIN -> Firebase console -> `smsMeta/pins/<code>` holds only `salt`/`hash`, never the PIN.
3. Before the PIN exists, a send says "isn't activated". With a wrong PIN: "Incorrect SMS PIN". 5 wrong: 30-minute lock.
4. Top up +50 -> shows on admin table AND the school's SMS tab. Approve the same request twice -> credited once.
5. Send one real SMS to your own number with the right PIN: arrives, balance drops by the segments used.
6. Change a test school's code: balance + PIN still work under the new code. Delete a test school: `schools/<code>/sms` is gone.
7. Password-reset code by SMS still arrives (needs no PIN, uses no school credit).

## Known limits (be aware)
- **Staff passwords are stored in plain text inside each school's synced data**, and that data is readable by any
  signed-in browser that knows the school code (including the Parent Portal's lookup). The SMS PIN does NOT depend on
  that data, so money is safe from it - but the passwords, learner records and parent phone numbers are exposed to
  anyone technical who knows a school code. Fixing this properly means hashing passwords and moving to server-issued
  Firebase login tokens with per-school rules. It changes login, sync and the Parent Portal - plan it as its own project.
- The PIN is only as private as the DOS keeps it. Reset it (Issue / Reset PIN) if staff change.
- Vercel Hobby is for non-commercial use; move to Pro once you charge schools.
