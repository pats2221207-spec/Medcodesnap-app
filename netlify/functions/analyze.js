exports.handler = async function(event, context) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
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
        headers: { "Access-Control-Allow-Origin": "*" },
        body: JSON.stringify({ error: "API error", details: data })
      };
    }

    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      },
      body: JSON.stringify(result)
    };

  } catch (err) {
    console.error("Function error:", err);
    return {
      statusCode: 500,
      headers: { "Access-Control-Allow-Origin": "*" },
      body: JSON.stringify({ error: err.message })
    };
  }
};
