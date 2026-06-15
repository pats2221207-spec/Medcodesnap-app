// AWS Lambda handler for medcodesnap-analyze
// Converted from netlify/functions/analyze.js
//
// Deploy behind API Gateway (REST API, Lambda Proxy integration) on:
//   POST /api/analyze
//
// Required environment variables:
//   OPENAI_API_KEY              - OpenAI API key used for note analysis
//   GOOGLE_SERVICE_ACCOUNT_JSON  - Full JSON key for the Google service account
//                                  (medcodesnap-sheets-writer@medcodesnap.iam.gserviceaccount.com)
//                                  used to append rows to the results Google Sheet.
//                                  If unset, Sheets sync is skipped (results are still returned).

const crypto = require("crypto");

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST,OPTIONS"
};

// The Google Sheet that receives a row per analyzed note:
//   A = Patient Name
//   B = Date of Service
//   C = Diagnoses
//   D = ICD-10 Codes
//   E = Record Key (YYYYMMDD-HHMMSS)
//   F = Date Submitted (ISO 8601)
const RESULTS_SHEET_ID = "1FPxZOjNuL5EkEg7lfJX8HPBhdiTHUg7NafUogH33pfU";

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Exchange the service account's private key for a short-lived OAuth2
// access token scoped to Sheets, via a signed JWT (RFC 7523).
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

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedClaimSet = base64url(JSON.stringify(claimSet));
  const signInput = `${encodedHeader}.${encodedClaimSet}`;

  const signature = crypto.createSign("RSA-SHA256").update(signInput).sign(creds.private_key);
  const jwt = `${signInput}.${base64url(signature)}`;

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:
      `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}` +
      `&assertion=${jwt}`
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`Google token error: ${JSON.stringify(data)}`);
  }
  return data.access_token;
}

function formatRecordKey(d) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}` +
    `-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
  );
}

// Append a row with this note's results to the results Google Sheet.
// Returns true on success, false on any failure (logged, never thrown) so
// the caller can still return the analysis results to the client.
async function syncToGoogleSheet(result) {
  try {
    const credsJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (!credsJson) {
      console.log("Sheets sync skipped: GOOGLE_SERVICE_ACCOUNT_JSON is not configured");
      return false;
    }

    const creds = JSON.parse(credsJson);
    const accessToken = await getGoogleAccessToken(creds);

    const now = new Date();
    const row = [
      result.patient_name || "",
      result.note_date || "",
      result.diagnoses_comma_separated || "",
      result.icd10_codes_comma_separated || "",
      formatRecordKey(now),
      now.toISOString()
    ];

    const url =
      `https://sheets.googleapis.com/v4/spreadsheets/${RESULTS_SHEET_ID}` +
      `/values/Sheet1!A:F:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ values: [row] })
    });

    const data = await resp.json();
    if (!resp.ok) {
      console.log("Sheets append error:", JSON.stringify(data));
      return false;
    }
    return true;
  } catch (err) {
    console.log("Sheets sync failed:", err.message);
    return false;
  }
}

exports.handler = async function (event, context) {
  // Handle CORS preflight requests
  const method = event.httpMethod || (event.requestContext && event.requestContext.http && event.requestContext.http.method);
  if (method === "OPTIONS") {
    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: ""
    };
  }
  if (method !== "POST") {
    return {
      statusCode: 405,
      headers: CORS_HEADERS,
      body: "Method Not Allowed"
    };
  }
  try {
    const { imageData, mediaType } = JSON.parse(event.body);
    const PROMPT = `You are an expert medical coder. Analyze this clinical note image.
Extract the following and return ONLY a raw JSON object — no backticks, no markdown, no explanation. Start with { and end with }.
Required fields:
- record_key: LASTNAME_FIRSTNAME_MMDDYYYY (from note date, no spaces)
- patient_name: First and Last name
- note_date: MM/DD/YYYY
- date_missing: true or false
- diagnoses_comma_separated: all diagnoses as a single comma-separated string
- icd10_codes_comma_separated: all ICD-10-CM codes as a single comma-separated string. Assign correct current ICD-10-CM codes based on your medical coding knowledge even if not explicitly written in the note.
If any field cannot be found, use "NOT FOUND".`;
    const isTextNote = mediaType === "text/plain";
    let messages;
    if (isTextNote) {
      // .txt uploads (e.g. the "Try a Sample Note" feature) — read the note
      // text directly and send it to OpenAI as plain text, skipping the
      // image/vision processing path entirely.
      const noteText = Buffer.from(imageData, "base64").toString("utf-8");
      messages = [
        {
          role: "system",
          content: "You are an expert medical coder. Return only raw JSON, no markdown, no backticks."
        },
        {
          role: "user",
          content: `${PROMPT}\n\nCLINICAL NOTE TEXT:\n${noteText}`
        }
      ];
    } else {
      messages = [
        {
          role: "system",
          content: "You are an expert medical coder. Return only raw JSON, no markdown, no backticks."
        },
        {
          role: "user",
          content: [
            {
              type: "image_url",
              image_url: {
                url: `data:${mediaType};base64,${imageData}`,
                detail: "auto"
              }
            },
            {
              type: "text",
              text: PROMPT
            }
          ]
        }
      ];
    }
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o",
        max_tokens: 1024,
        response_format: { type: "json_object" },
        messages
      })
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("OpenAI error:", data);
      return {
        statusCode: 500,
        headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
        body: JSON.stringify({ error: "API error", details: data })
      };
    }
    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    // Append this result to the customer's results Google Sheet. Never lets
    // a Sheets failure break the response to the client.
    result.sheet_synced = await syncToGoogleSheet(result);

    return {
      statusCode: 200,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify(result)
    };
  } catch (err) {
    console.error("Function error:", err);
    return {
      statusCode: 500,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ error: err.message })
    };
  }
};
