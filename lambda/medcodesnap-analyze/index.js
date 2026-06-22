// AWS Lambda handler for medcodesnap-analyze
// Deploy behind API Gateway (REST API, Lambda Proxy integration) on:
// POST /api/analyze → action:"analyze"
// POST /api/analyze → action:"syncSheet"
// POST /api/analyze → action:"adminListUsers" / "adminUpdateUser" / "adminCreateUser" (Phase 10, /admin — all three require
//                      body.accessToken to belong to patty@medcodesnap.com, verified server-side via Cognito GetUser)
// POST /api/analyze → Stripe webhook (detected via Stripe-Signature header, see 3.4)
//
// Required environment variables:
// AZURE_OPENAI_KEY - Azure OpenAI API key
// AZURE_OPENAI_ENDPOINT - Azure OpenAI resource endpoint (e.g. https://<resource>.cognitiveservices.azure.com)
// AZURE_OPENAI_DEPLOYMENT_NAME - Azure OpenAI deployment name (e.g. gpt-4o)
// GOOGLE_SERVICE_ACCOUNT_JSON - Full JSON key for the Google service account
// STRIPE_WEBHOOK_SECRET - Signing secret (whsec_...) from the Stripe webhook endpoint config
// COGNITO_APP_CLIENT_ID - (optional) Cognito app client ID used for the adminCreateUser → ForgotPassword call; defaults to the same client /login already uses
//
// IAM: in addition to the DynamoDB + Cognito (AdminUpdateUserAttributes, ListUsers) permissions this
// function already needed, the Phase 10 admin actions require the execution role to also be able to call
// cognito-idp:GetUser, cognito-idp:AdminCreateUser, and cognito-idp:ForgotPassword on this user pool/app client.

const crypto = require("crypto");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, GetCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");
const {
CognitoIdentityProviderClient,
AdminUpdateUserAttributesCommand,
ListUsersCommand,
GetUserCommand,
AdminCreateUserCommand,
ForgotPasswordCommand
} = require("@aws-sdk/client-cognito-identity-provider");

const CORS_HEADERS = {
"Access-Control-Allow-Origin": "*",
"Access-Control-Allow-Headers": "Content-Type, Stripe-Signature",
"Access-Control-Allow-Methods": "POST,OPTIONS"
};

// ── Pending Sheets carry-over store (3.3) ────────────────────────────────────
// Temporary, PHI-bearing record keyed by the signed-up user's Cognito `sub`.
// TTL attribute "ttl" (epoch seconds) is enabled on the table so DynamoDB
// auto-expires anything that's never picked up (1 hour, matching the brief).
const ddbClient = new DynamoDBClient({ region: process.env.AWS_REGION || "us-west-1" });
const ddb = DynamoDBDocumentClient.from(ddbClient);
const PENDING_SHEETS_TABLE = process.env.PENDING_SHEETS_TABLE || "medcodesnap-pending-sheets";
const PENDING_SHEETS_TTL_SECONDS = 3600; // 1 hour

// ── Stripe webhook → trial/billing status (3.4) ──────────────────────────────
// Source of truth for "did this person actually pay." The redirect-back path
// (frontend) is just an instant-unlock UI nicety that polls for the same
// custom:billing_status attribute this webhook sets — it never writes the
// attribute itself, so there's no spoofable "trust the URL" shortcut.
const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION || "us-west-1" });
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || "us-west-1_vhYzjYK3K";
const STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutes — matches Stripe's own default, guards against replay

// ── Admin dashboard (Phase 10) ───────────────────────────────────────────────
// Internal-only tooling at /admin so the site owner can manage users without
// touching the Cognito console directly. Every action below is gated to this
// one hardcoded address — there is no "admin role" attribute, just this check.
const ADMIN_EMAIL = "patty@medcodesnap.com";

// The public app client used by /login's own SignUp/ForgotPassword calls
// (see login/index.html and index.html). adminCreateUser reuses this same
// client to kick off the ForgotPassword flow for newly-created clients.
const COGNITO_APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID || "3cst6juv3rbrn7b2h4efkfr3hj";

// Allowed values for a manual custom:billing_status write from the admin
// tools. "active" and "trialing" are the exact strings the rest of this app
// already writes — "active" by activateBillingForSub() below (Stripe
// webhook), "trialing" by index.html right after a public signup — reused
// verbatim rather than inventing new spellings. "expired" and "canceled"
// are net-new states for admins to manually flag accounts whose trial ran
// out or who canceled outside Stripe. Importantly, none of these three
// non-"active" values grant dashboard access by themselves — dashboard's
// checkPaywall() (dashboard/index.html) only ever unlocks on the exact
// string "active", so adding them doesn't change any existing gating.
const ADMIN_BILLING_STATUSES = ["active", "trialing", "expired", "canceled"];

// Confirms the caller of an admin-only action is genuinely signed in as
// ADMIN_EMAIL. This resolves the caller's OWN Cognito access token via
// GetUser — the same call dashboard/index.html already makes (see
// fetchBillingState()) to read billing_status for the paywall — so it is
// Cognito itself, not the request body, that says who the caller is. A
// missing, expired, forged, or otherwise-invalid token, or a valid token
// for any account other than ADMIN_EMAIL, returns false. Nothing in this
// function trusts a claimed `email` field from the request body.
async function verifyAdminCaller(accessToken) {
if (!accessToken || typeof accessToken !== "string") return false;
try {
const data = await cognitoClient.send(new GetUserCommand({ AccessToken: accessToken }));
const attrs = data.UserAttributes || [];
const email = (attrs.find(a => a.Name === "email") || {}).Value || null;
return email === ADMIN_EMAIL;
} catch (err) {
// Invalid/expired/revoked token, or any other GetUser failure — never
// treat this as an authenticated admin.
return false;
}
}

function forbiddenAdminResponse() {
return { statusCode: 403, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "Forbidden" }) };
}

function getHeader(event, name) {
const headers = event.headers || {};
const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
return key ? headers[key] : null;
}

// Hand-rolled Stripe webhook signature verification (no `stripe` npm package,
// matching how this Lambda already hand-rolls the Google OAuth JWT above).
// Stripe-Signature header format: "t=<timestamp>,v1=<sig>[,v1=<sig2>...]"
// Signed payload: "<timestamp>.<rawBody>", HMAC-SHA256 with the webhook
// secret, hex digest, compared with a constant-time check.
function verifyStripeSignature(rawBody, sigHeader, secret) {
if (!sigHeader || !secret) return false;

const timestampPart = sigHeader.split(",").find(p => p.startsWith("t="));
const timestamp = timestampPart ? timestampPart.slice(2) : null;
const signatures = sigHeader.split(",").filter(p => p.startsWith("v1=")).map(p => p.slice(3));
if (!timestamp || !signatures.length) return false;

const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(timestamp, 10));
if (!Number.isFinite(age) || age > STRIPE_WEBHOOK_TOLERANCE_SECONDS) return false;

const signedPayload = `${timestamp}.${rawBody}`;
const expected = crypto.createHmac("sha256", secret).update(signedPayload, "utf8").digest("hex");

return signatures.some(sig => {
if (sig.length !== expected.length) return false;
try { return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex")); }
catch (e) { return false; }
});
}

// Resolve the Cognito user for a given sub and set custom:billing_status=active.
// For this pool, Username is an auto-generated UUID equal to sub (not email),
// so the direct path works in the common case; ListUsers-by-sub is a defensive
// fallback in case that assumption ever changes.
async function activateBillingForSub(sub) {
try {
await cognitoClient.send(new AdminUpdateUserAttributesCommand({
UserPoolId: USER_POOL_ID,
Username: sub,
UserAttributes: [{ Name: "custom:billing_status", Value: "active" }]
}));
return true;
} catch (err) {
if (err.name !== "UserNotFoundException") throw err;
}

const found = await cognitoClient.send(new ListUsersCommand({
UserPoolId: USER_POOL_ID,
Filter: `sub = "${sub}"`,
Limit: 1
}));
const user = (found.Users || [])[0];
if (!user) return false;

await cognitoClient.send(new AdminUpdateUserAttributesCommand({
UserPoolId: USER_POOL_ID,
Username: user.Username,
UserAttributes: [{ Name: "custom:billing_status", Value: "active" }]
}));
return true;
}

// ── Google OAuth helper ──────────────────────────────────────────────────────

function base64url(input) {
const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getGoogleAccessToken(creds) {
const now = Math.floor(Date.now() / 1000);
const header = { alg: "RS256", typ: "JWT" };
const claimSet = {
iss: creds.client_email,
scope: "https://www.googleapis.com/auth/spreadsheets",
aud: "https://oauth2.googleapis.com/token",
exp: now + 3600,
iat: now
};
const signInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claimSet))}`;
const signature = crypto.createSign("RSA-SHA256").update(signInput).sign(creds.private_key);
const jwt = `${signInput}.${base64url(signature)}`;

const resp = await fetch("https://oauth2.googleapis.com/token", {
method: "POST",
headers: { "Content-Type": "application/x-www-form-urlencoded" },
body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${jwt}`
});
const data = await resp.json();
if (!resp.ok) throw new Error(`Google token error: ${JSON.stringify(data)}`);
return data.access_token;
}

// ── Record Key builder ───────────────────────────────────────────────────────
// Format: LASTNAME_FIRSTNAME_MMDDYYYY_DOSMMDDYYYY
function buildRecordKey(patientName, dob, dos) {
// patientName expected as "Last, First" or "First Last"
let last = "", first = "";
if (patientName && patientName.includes(",")) {
[last, first] = patientName.split(",").map(s => s.trim().toUpperCase().replace(/\s+/g, ""));
} else if (patientName) {
const parts = patientName.trim().toUpperCase().split(/\s+/);
first = parts[0] || "";
last = parts.slice(1).join("") || "";
}

// Convert MM/DD/YYYY → MMDDYYYY
function toMMDDYYYY(dateStr) {
if (!dateStr) return "";
const cleaned = dateStr.replace(/[^0-9\/\-]/g, "");
// Already MM/DD/YYYY
if (/^\d{2}\/\d{2}\/\d{4}$/.test(cleaned)) return cleaned.replace(/\//g, "");
// YYYY-MM-DD
if (/^\d{4}-\d{2}-\d{2}$/.test(cleaned)) {
const [y, m, d] = cleaned.split("-");
return `${m}${d}${y}`;
}
return cleaned.replace(/[^0-9]/g, "");
}

return `${last}_${first}_${toMMDDYYYY(dob)}_${toMMDDYYYY(dos)}`;
}

// ── Sheets: get all values in a tab ─────────────────────────────────────────
async function getSheetValues(sheetId, tabName, accessToken) {
const range = encodeURIComponent(`${tabName}!A:G`);
const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}`;
const resp = await fetch(url, {
headers: { "Authorization": `Bearer ${accessToken}` }
});
const data = await resp.json();
if (!resp.ok) throw new Error(`Sheets read error: ${JSON.stringify(data)}`);
return data.values || [];
}

// ── Sheets: find row index by Record Key (col F = index 5) ──────────────────
function findRowByRecordKey(rows, recordKey) {
for (let i = 1; i < rows.length; i++) { // skip header row
if ((rows[i][5] || "") === recordKey) return i + 1; // 1-based sheet row
}
return -1;
}

// ── Sheets: append a new row ─────────────────────────────────────────────────
async function appendRow(sheetId, tabName, row, accessToken) {
const range = encodeURIComponent(`${tabName}!A:G`);
const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;
const resp = await fetch(url, {
method: "POST",
headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
body: JSON.stringify({ values: [row] })
});
const data = await resp.json();
if (!resp.ok) throw new Error(`Sheets append error: ${JSON.stringify(data)}`);
return data;
}

// ── Sheets: update an existing row ──────────────────────────────────────────
async function updateRow(sheetId, tabName, rowNum, row, accessToken) {
const range = encodeURIComponent(`${tabName}!A${rowNum}:G${rowNum}`);
const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}?valueInputOption=USER_ENTERED`;
const resp = await fetch(url, {
method: "PUT",
headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
body: JSON.stringify({ values: [row] })
});
const data = await resp.json();
if (!resp.ok) throw new Error(`Sheets update error: ${JSON.stringify(data)}`);
return data;
}

// ── Sheets: get all sheet (tab) names ───────────────────────────────────────
async function getSheetTabs(sheetId, accessToken) {
const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}?fields=sheets.properties.title`;
const resp = await fetch(url, {
headers: { "Authorization": `Bearer ${accessToken}` }
});
const data = await resp.json();
if (!resp.ok) throw new Error(`Sheets metadata error: ${JSON.stringify(data)}`);
return (data.sheets || []).map(s => s.properties.title);
}

// ── Main handler ─────────────────────────────────────────────────────────────
exports.handler = async function (event) {
const method = event.httpMethod || (event.requestContext && event.requestContext.http && event.requestContext.http.method);

if (method === "OPTIONS") return { statusCode: 200, headers: CORS_HEADERS, body: "" };
if (method !== "POST") return { statusCode: 405, headers: CORS_HEADERS, body: "Method Not Allowed" };

// ── Stripe webhook (3.4) ── detected by Stripe-Signature header, handled
// before the action-based routing below (which expects our own JSON shape).
// Must use the RAW body string for signature verification — JSON.parse
// happens only after the signature checks out.
const stripeSig = getHeader(event, "Stripe-Signature");
if (stripeSig) {
const rawBody = event.body || "";
const secret = process.env.STRIPE_WEBHOOK_SECRET;
if (!verifyStripeSignature(rawBody, stripeSig, secret)) {
console.error("Stripe webhook signature verification failed");
return { statusCode: 400, headers: CORS_HEADERS, body: "Invalid signature" };
}
try {
const stripeEvent = JSON.parse(rawBody);
if (stripeEvent.type === "checkout.session.completed") {
const session = stripeEvent.data.object;
const sub = session.client_reference_id;
if (sub && session.payment_status === "paid") {
await activateBillingForSub(sub);
} else {
console.error("checkout.session.completed missing client_reference_id or not paid", { hasSub: !!sub, payment_status: session.payment_status });
}
}
// Other event types Stripe might send to this same endpoint are
// acknowledged but otherwise ignored — checkout.session.completed
// (filtered to payment_status:"paid") is the source of truth here.
return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ received: true }) };
} catch (err) {
console.error("Stripe webhook handling error:", err.name || "Error", "-", err.message);
return { statusCode: 500, headers: CORS_HEADERS, body: "Webhook handler error" };
}
}

try {
const body = JSON.parse(event.body || "{}");
const action = body.action || "analyze";

// ── action: savePendingSheet ── write carry-over record keyed by sub ────
// PHI-bearing, short-lived (TTL on the table handles auto-expiry as a
// backstop; the dashboard also explicitly deletes it after reading it).
if (action === "savePendingSheet") {
const { sub, data: d } = body;
if (!sub) return { statusCode: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "sub is required" }) };
const ttl = Math.floor(Date.now() / 1000) + PENDING_SHEETS_TTL_SECONDS;
await ddb.send(new PutCommand({
TableName: PENDING_SHEETS_TABLE,
Item: { sub, data: d, ttl }
}));
return { statusCode: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ success: true }) };
}

// ── action: getPendingSheet ── read carry-over record by sub ────────────
if (action === "getPendingSheet") {
const { sub } = body;
if (!sub) return { statusCode: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "sub is required" }) };
const result = await ddb.send(new GetCommand({ TableName: PENDING_SHEETS_TABLE, Key: { sub } }));
return {
statusCode: 200,
headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
body: JSON.stringify({ found: !!result.Item, data: result.Item ? result.Item.data : null })
};
}

// ── action: deletePendingSheet ── delete carry-over record by sub ───────
if (action === "deletePendingSheet") {
const { sub } = body;
if (!sub) return { statusCode: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "sub is required" }) };
await ddb.send(new DeleteCommand({ TableName: PENDING_SHEETS_TABLE, Key: { sub } }));
return { statusCode: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ success: true }) };
}

// ── action: adminListUsers ── list every signed-up user (Phase 10) ──────
// Admin-only (verifyAdminCaller). Returns the fields the /admin table
// needs: email, sub, current billing_status/trial_start, and signup date.
if (action === "adminListUsers") {
if (!(await verifyAdminCaller(body.accessToken))) return forbiddenAdminResponse();

const users = [];
let paginationToken;
do {
const page = await cognitoClient.send(new ListUsersCommand({
UserPoolId: USER_POOL_ID,
Limit: 60,
PaginationToken: paginationToken
}));
for (const u of (page.Users || [])) {
const attrs = u.Attributes || [];
const getAttr = name => (attrs.find(a => a.Name === name) || {}).Value || null;
users.push({
sub: getAttr("sub"),
email: getAttr("email"),
billing_status: getAttr("custom:billing_status"),
trial_start: getAttr("custom:trial_start"),
created: u.UserCreateDate ? new Date(u.UserCreateDate).toISOString() : null
});
}
paginationToken = page.PaginationToken;
} while (paginationToken);

return { statusCode: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ users }) };
}

// ── action: adminUpdateUser ── manually set billing_status and/or
// trial_start for one existing user (Phase 10). Admin-only.
if (action === "adminUpdateUser") {
if (!(await verifyAdminCaller(body.accessToken))) return forbiddenAdminResponse();

const { sub, billing_status, trial_start } = body;
const jsonHeaders = { ...CORS_HEADERS, "Content-Type": "application/json" };

if (!sub || typeof sub !== "string") {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "sub is required" }) };
}
if (billing_status === undefined && trial_start === undefined) {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "Provide billing_status and/or trial_start" }) };
}
if (billing_status !== undefined && !ADMIN_BILLING_STATUSES.includes(billing_status)) {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: `billing_status must be one of: ${ADMIN_BILLING_STATUSES.join(", ")}` }) };
}
// trial_start is stored as an epoch-ms string — String(Date.now()), see
// index.html's signup flow — NOT an ISO date string, even though an ISO
// date is what a date picker naturally produces. The admin frontend is
// responsible for converting the picked date to this format before
// calling this action, so dashboard's existing checkPaywall() math
// (parseInt(trial_start, 10) against Date.now()) keeps working unchanged.
if (trial_start !== undefined && (typeof trial_start !== "string" || !/^\d+$/.test(trial_start))) {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "trial_start must be an epoch-ms timestamp string (digits only)" }) };
}

const userAttributes = [];
if (billing_status !== undefined) userAttributes.push({ Name: "custom:billing_status", Value: billing_status });
if (trial_start !== undefined) userAttributes.push({ Name: "custom:trial_start", Value: trial_start });

await cognitoClient.send(new AdminUpdateUserAttributesCommand({
UserPoolId: USER_POOL_ID,
Username: sub,
UserAttributes: userAttributes
}));

return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
}

// ── action: adminCreateUser ── manually add a new client (Phase 10) ─────
// Admin-only. Creates the Cognito user without a temporary password and
// without pre-verifying their email, then triggers the same ForgotPassword
// flow /login's "Forgot password" modal already uses so the new client
// receives a reset-code email and sets their own password on first login —
// same self-service password step as a normal signup, just skipping the
// public signup form. Cognito treats a successfully-used password-reset
// code as proof of mailbox ownership, so this still amounts to a real
// email-verification step, not a shortcut around one.
if (action === "adminCreateUser") {
if (!(await verifyAdminCaller(body.accessToken))) return forbiddenAdminResponse();

const { email, billing_status, trial_start } = body;
const jsonHeaders = { ...CORS_HEADERS, "Content-Type": "application/json" };

if (!email || typeof email !== "string") {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "email is required" }) };
}
if (billing_status !== undefined && !ADMIN_BILLING_STATUSES.includes(billing_status)) {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: `billing_status must be one of: ${ADMIN_BILLING_STATUSES.join(", ")}` }) };
}
if (trial_start !== undefined && (typeof trial_start !== "string" || !/^\d+$/.test(trial_start))) {
return { statusCode: 400, headers: jsonHeaders, body: JSON.stringify({ error: "trial_start must be an epoch-ms timestamp string (digits only)" }) };
}

const userAttributes = [{ Name: "email", Value: email }];
// Deliberately not setting email_verified — see comment above the
// action block for why that's intentional, not an oversight.
if (billing_status !== undefined) userAttributes.push({ Name: "custom:billing_status", Value: billing_status });
if (trial_start !== undefined) userAttributes.push({ Name: "custom:trial_start", Value: trial_start });

try {
await cognitoClient.send(new AdminCreateUserCommand({
UserPoolId: USER_POOL_ID,
Username: email,
UserAttributes: userAttributes,
// No TemporaryPassword, and MessageAction:"SUPPRESS" so Cognito never
// emails the auto-generated one — the ForgotPassword call right below
// is the actual "set your password" path the user gets instead.
MessageAction: "SUPPRESS"
}));
} catch (err) {
if (err.name === "UsernameExistsException") {
return { statusCode: 409, headers: jsonHeaders, body: JSON.stringify({ error: "A user with that email already exists" }) };
}
throw err;
}

await cognitoClient.send(new ForgotPasswordCommand({
ClientId: COGNITO_APP_CLIENT_ID,
Username: email
}));

return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
}

// ── action: getTabs ── return tab list for a sheet ──────────────────────
if (action === "getTabs") {
const credsJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
if (!credsJson) return { statusCode: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "GOOGLE_SERVICE_ACCOUNT_JSON not configured" }) };
const creds = JSON.parse(credsJson);
const accessToken = await getGoogleAccessToken(creds);
const sheetId = body.sheetId || process.env.RESULTS_SHEET_ID;
const tabs = await getSheetTabs(sheetId, accessToken);
return { statusCode: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ tabs }) };
}

// ── action: checkDuplicate ── does a record key already exist? ──────────
if (action === "checkDuplicate") {
const credsJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
if (!credsJson) return { statusCode: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "GOOGLE_SERVICE_ACCOUNT_JSON not configured" }) };
const { sheetId, tabName, recordKey } = body;
const creds = JSON.parse(credsJson);
const accessToken = await getGoogleAccessToken(creds);
const targetSheetId = sheetId || process.env.RESULTS_SHEET_ID;
const rows = await getSheetValues(targetSheetId, tabName, accessToken);
const rowNum = findRowByRecordKey(rows, recordKey);
return {
statusCode: 200,
headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
body: JSON.stringify({ exists: rowNum > 0, rowNum: rowNum > 0 ? rowNum : null })
};
}

// ── action: syncSheet ── write confirmed data from frontend to Sheets ────
if (action === "syncSheet") {
const credsJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
if (!credsJson) return { statusCode: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "GOOGLE_SERVICE_ACCOUNT_JSON not configured" }) };

const { sheetId, tabName, operation, data: d } = body;
const creds = JSON.parse(credsJson);
const accessToken = await getGoogleAccessToken(creds);

// Col D = diagnosis descriptions only; Col E = ICD-10 codes only (no descriptions)
const diagStr = Array.isArray(d.diagnoses) ? d.diagnoses.join(", ") : (d.diagnoses || "");
const codesStr = Array.isArray(d.icd10Codes)
? d.icd10Codes.map(c => c.code).join(", ")
: (d.icd10Codes || "");

const recordKey = buildRecordKey(d.patientName, d.dob, d.dos);
const now = new Date();
const dateSubmitted = `${String(now.getMonth()+1).padStart(2,"0")}/${String(now.getDate()).padStart(2,"0")}/${now.getFullYear()}`;

// Columns: A=Patient Name, B=DOB, C=DOS, D=Diagnoses, E=ICD-10 Codes, F=Record Key, G=Date Submitted
const row = [
d.patientName || "",
d.dob || "",
d.dos || "",
diagStr,
codesStr,
recordKey,
dateSubmitted
];

const targetSheetId = sheetId || process.env.RESULTS_SHEET_ID;

if (operation === "update") {
const rows = await getSheetValues(targetSheetId, tabName, accessToken);
const rowNum = findRowByRecordKey(rows, recordKey);
if (rowNum > 0) {
await updateRow(targetSheetId, tabName, rowNum, row, accessToken);
} else {
await appendRow(targetSheetId, tabName, row, accessToken);
}
} else {
await appendRow(targetSheetId, tabName, row, accessToken);
}

return {
statusCode: 200,
headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
body: JSON.stringify({ success: true, recordKey, tabName })
};
}

// ── action: analyze ── run GPT-4o, return structured JSON, no Sheets write
const { imageData, mediaType } = body;

const PROMPT = `You are an expert medical coder. Analyze this clinical note and extract the following information.
Return ONLY a raw JSON object — no backticks, no markdown, no explanation. Start with { and end with }.

Required fields:
- patient_name: Full name in "Last, First" format (e.g. "Smith, Jane"). Empty string if not found.
- dob: Date of birth in MM/DD/YYYY format. Empty string if not found.
- dos: Date of service in MM/DD/YYYY format. Empty string if not found.
- diagnoses: Array of strings, each a distinct diagnosis (e.g. ["Type 2 diabetes mellitus", "Hypertension"]). Empty array if none found.
- icd10_codes: Array of objects, each with "code" (e.g. "E11.65") and "description" (e.g. "Type 2 diabetes mellitus with hyperglycemia"). Assign correct current ICD-10-CM codes based on your medical coding knowledge even if not explicitly written. Empty array if none found.

If any field cannot be determined, return it as empty string or empty array — never use "NOT FOUND".`;

let messages;
if (mediaType === "text/plain") {
const noteText = Buffer.from(imageData, "base64").toString("utf-8");
messages = [
{ role: "system", content: "You are an expert medical coder. Return only raw JSON, no markdown, no backticks." },
{ role: "user", content: `${PROMPT}\n\nCLINICAL NOTE TEXT:\n${noteText}` }
];
} else {
messages = [
{ role: "system", content: "You are an expert medical coder. Return only raw JSON, no markdown, no backticks." },
{
role: "user",
content: [
{ type: "image_url", image_url: { url: `data:${mediaType};base64,${imageData}`, detail: "auto" } },
{ type: "text", text: PROMPT }
]
}
];
}

const AZURE_OPENAI_API_VERSION = "2025-01-01-preview";
const azureEndpoint = (process.env.AZURE_OPENAI_ENDPOINT || "").replace(/\/+$/, "");
const azureDeployment = process.env.AZURE_OPENAI_DEPLOYMENT_NAME;
const azureUrl = `${azureEndpoint}/openai/deployments/${azureDeployment}/chat/completions?api-version=${AZURE_OPENAI_API_VERSION}`;

const response = await fetch(azureUrl, {
method: "POST",
headers: { "Content-Type": "application/json", "api-key": process.env.AZURE_OPENAI_KEY },
body: JSON.stringify({ max_tokens: 1024, response_format: { type: "json_object" }, messages })
});

const aiData = await response.json();
if (!response.ok) {
return { statusCode: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" }, body: JSON.stringify({ error: "API error", details: aiData }) };
}

const raw = aiData.choices?.[0]?.message?.content || "";
const clean = raw.replace(/```json|```/g, "").trim();
const result = JSON.parse(clean);

// Normalize: ensure arrays exist
if (!Array.isArray(result.diagnoses)) result.diagnoses = [];
if (!Array.isArray(result.icd10_codes)) result.icd10_codes = [];

// Pre-compute record key for frontend convenience
result.record_key = buildRecordKey(result.patient_name, result.dob, result.dos);

return {
statusCode: 200,
headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
body: JSON.stringify(result)
};

} catch (err) {
// PHI SAFETY: log only error name and message
console.error("Function error:", err.name || "Error", "-", err.message);
return {
statusCode: 500,
headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
body: JSON.stringify({ error: err.message })
};
}
};
