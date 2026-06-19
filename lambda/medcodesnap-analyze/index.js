// AWS Lambda handler for medcodesnap-analyze
// Deploy behind API Gateway (REST API, Lambda Proxy integration) on:
//   POST /api/analyze     → action:"analyze"
//   POST /api/analyze     → action:"syncSheet"
//
// Required environment variables:
//   AZURE_OPENAI_KEY              - Azure OpenAI API key
//   AZURE_OPENAI_ENDPOINT         - Azure OpenAI resource endpoint (e.g. https://<resource>.cognitiveservices.azure.com)
//   AZURE_OPENAI_DEPLOYMENT_NAME  - Azure OpenAI deployment name (e.g. gpt-4o)
//   GOOGLE_SERVICE_ACCOUNT_JSON   - Full JSON key for the Google service account

const crypto = require("crypto");

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST,OPTIONS"
};

// ── Google OAuth helper ──────────────────────────────────────────────────────

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getGoogleAccessToken(creds) {
  const now = Math.floor(Date.now() / 1000);
  const header   = { alg: "RS256", typ: "JWT" };
  const claimSet = {
    iss:   creds.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud:   "https://oauth2.googleapis.com/token",
    exp:   now + 3600,
    iat:   now
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
    last  = parts.slice(1).join("") || "";
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

  try {
    const body = JSON.parse(event.body || "{}");
    const action = body.action || "analyze";

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
      const diagStr  = Array.isArray(d.diagnoses) ? d.diagnoses.join(", ") : (d.diagnoses || "");
      const codesStr = Array.isArray(d.icd10Codes)
        ? d.icd10Codes.map(c => c.code).join(", ")
        : (d.icd10Codes || "");

      const recordKey = buildRecordKey(d.patientName, d.dob, d.dos);
      const now = new Date();
      const dateSubmitted = `${String(now.getMonth()+1).padStart(2,"0")}/${String(now.getDate()).padStart(2,"0")}/${now.getFullYear()}`;

      // Columns: A=Patient Name, B=DOB, C=DOS, D=Diagnoses, E=ICD-10 Codes, F=Record Key, G=Date Submitted
      const row = [
        d.patientName || "",
        d.dob         || "",
        d.dos         || "",
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
        { role: "user",   content: `${PROMPT}\n\nCLINICAL NOTE TEXT:\n${noteText}` }
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
    const azureEndpoint   = (process.env.AZURE_OPENAI_ENDPOINT || "").replace(/\/+$/, "");
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

    const raw    = aiData.choices?.[0]?.message?.content || "";
    const clean  = raw.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    // Normalize: ensure arrays exist
    if (!Array.isArray(result.diagnoses))  result.diagnoses  = [];
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
