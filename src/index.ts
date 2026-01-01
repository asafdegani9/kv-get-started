// src/index.ts
// Full Worker file with a homepage redirect:
// Visiting https://eca-info.org/ will 301-redirect to https://aln.co.il/
// All your existing link endpoints (/health, /api/register, /p/<token>, /t/<token>.png, /x/<token>) keep working.

export default {
  async fetch(request: Request, env: any) {
    const url = new URL(request.url);

    // ======================
    // HOME REDIRECT (ONLY "/")
    // ======================
    // Redirect only the exact homepage. We intentionally do NOT redirect
    // /p/*, /t/*, /x/*, /api/*, /health
    if ((url.pathname === "/" || url.pathname === "") && request.method === "GET") {
      return Response.redirect("https://aln.co.il/", 301);
    }
    // Optional: handle HEAD on homepage as well (some clients check with HEAD first)
    if ((url.pathname === "/" || url.pathname === "") && request.method === "HEAD") {
      return new Response(null, {
        status: 301,
        headers: { Location: "https://aln.co.il/" }
      });
    }

    // ======================
    // 1) HEALTH
    // ======================
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }

    // ======================
    // 2) REGISTER TOKEN -> pdf_key + thumb_key  (protected)
    // POST /api/register
    // Body: { pdf_key: "...", thumb_key: "...", ttl_days?: 30, token?: "optional" }
    // ======================
    if (url.pathname === "/api/register" && request.method === "POST") {
      const apiKey = request.headers.get("X-API-Key") || "";
      if (!env.API_KEY || apiKey !== env.API_KEY) {
        return json({ error: "Unauthorized" }, 401);
      }

      const body = await request.json().catch(() => null);
      if (!body) return json({ error: "Bad JSON" }, 400);

      const pdfKey = typeof body.pdf_key === "string" ? body.pdf_key.trim() : "";
      const thumbKey = typeof body.thumb_key === "string" ? body.thumb_key.trim() : "";
      if (!pdfKey) return json({ error: "Missing pdf_key" }, 400);
      if (!thumbKey) return json({ error: "Missing thumb_key" }, 400);

      const ttlDays =
        Number.isFinite(body.ttl_days) ? Math.max(1, Math.floor(body.ttl_days)) : 30;

      const now = Math.floor(Date.now() / 1000);
      const expiresAt = now + ttlDays * 86400;

      const token =
        (typeof body.token === "string" && body.token.trim())
          ? body.token.trim()
          : generateToken(10);

      const record = {
        pdf_key: pdfKey,
        thumb_key: thumbKey,
        expires_at: expiresAt
      };

      await env.LINKS.put(token, JSON.stringify(record), { expirationTtl: ttlDays * 86400 });

      return json(
        {
          token,
          url: `https://${url.host}/x/${token}`,
          preview_url: `https://${url.host}/p/${token}`,
          thumb_url: `https://${url.host}/t/${token}.png`,
          expires_at: expiresAt
        },
        200
      );
    }

    // ======================
    // 3) PREVIEW PAGE: /p/<token> (GET or HEAD)
    // ======================
    const p = url.pathname.match(/^\/p\/([A-Za-z0-9_-]{6,64})$/);
    if (p && (request.method === "GET" || request.method === "HEAD")) {
      const token = p[1];

      const rec = await getRecord(env, token);
      if (rec.errorResponse) return rec.errorResponse;

      const pageUrl = `https://${url.host}/p/${token}`;
      const openUrl = `https://${url.host}/x/${token}`;
      const ogImage = `https://${url.host}/t/${token}.png`;

      if (request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store"
          }
        });
      }

      const html = `<!doctype html>
<html lang="he">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>מסמך לצפייה</title>

  <meta property="og:type" content="website" />
  <meta property="og:title" content="מסמך לצפייה" />
  <meta property="og:description" content="לחץ לפתיחת המסמך." />
  <meta property="og:image" content="${ogImage}" />
  <meta property="og:image:type" content="image/png" />
  <meta property="og:url" content="${pageUrl}" />
  <meta name="twitter:card" content="summary_large_image" />
</head>
<body style="font-family: Arial; padding: 24px;">
  <h2>המסמך מוכן לצפייה</h2>

  <div style="margin: 12px 0;">
    <img src="${ogImage}" alt="thumbnail"
         style="max-width: 100%; border: 1px solid #ddd; border-radius: 10px;" />
  </div>

  <p><a href="${openUrl}" style="font-size: 18px;">פתח את המסמך</a></p>
</body>
</html>`;

      return new Response(html, {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }

    // ======================
    // 4) THUMBNAIL: /t/<token>.png (GET or HEAD)
    // ======================
    const t = url.pathname.match(/^\/t\/([A-Za-z0-9_-]{6,64})\.png$/);
    if (t && (request.method === "GET" || request.method === "HEAD")) {
      const token = t[1];

      const rec = await getRecord(env, token);
      if (rec.errorResponse) return rec.errorResponse;

      // HEAD: return headers only (helps WhatsApp/Meta crawlers)
      if (request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          headers: {
            "Content-Type": "image/png",
            "Cache-Control": "public, max-age=86400"
          }
        });
      }

      const cfg = getAwsCfg(env);
      if (cfg.errorResponse) return cfg.errorResponse;

      const presigned = await presignS3GetObject({
        bucket: cfg.bucket!,
        region: cfg.region!,
        key: rec.data!.thumb_key,
        accessKey: cfg.accessKey!,
        secretKey: cfg.secretKey!,
        expiresSeconds: 600
      });

      const resp = await fetch(presigned, { redirect: "follow" });
      if (!resp.ok) return new Response("Thumbnail not available", { status: 404 });

      const buf = await resp.arrayBuffer();
      return new Response(buf, {
        status: 200,
        headers: {
          "Content-Type": "image/png",
          "Cache-Control": "public, max-age=86400"
        }
      });
    }

    // ======================
    // 5) PDF REDIRECT: /x/<token> (GET or HEAD)
    // ======================
    const x = url.pathname.match(/^\/x\/([A-Za-z0-9_-]{6,64})$/);
    if (x && (request.method === "GET" || request.method === "HEAD")) {
      const token = x[1];

      const rec = await getRecord(env, token);
      if (rec.errorResponse) return rec.errorResponse;

      const cfg = getAwsCfg(env);
      if (cfg.errorResponse) return cfg.errorResponse;

      const presigned = await presignS3GetObject({
        bucket: cfg.bucket!,
        region: cfg.region!,
        key: rec.data!.pdf_key,
        accessKey: cfg.accessKey!,
        secretKey: cfg.secretKey!,
        expiresSeconds: 600
      });

      // For GET and HEAD: respond with redirect
      return new Response(null, {
        status: 302,
        headers: {
          Location: presigned,
          "Cache-Control": "no-store"
        }
      });
    }

    return new Response("Not found", { status: 404 });
  }
};

// ----------------------
// Helpers
// ----------------------

function json(obj: any, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

function generateToken(len = 10) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

async function getRecord(env: any, token: string): Promise<{ data?: any; errorResponse?: Response }> {
  const raw = await env.LINKS.get(token);
  if (!raw) return { errorResponse: new Response("Not found", { status: 404 }) };

  let rec: any;
  try { rec = JSON.parse(raw); }
  catch { return { errorResponse: new Response("Bad record", { status: 500 }) }; }

  const now = Math.floor(Date.now() / 1000);
  if (!rec.expires_at || now > rec.expires_at) {
    return { errorResponse: new Response("Expired", { status: 410 }) };
  }
  if (!rec.pdf_key || !rec.thumb_key) {
    return { errorResponse: new Response("Bad record", { status: 500 }) };
  }

  return { data: rec };
}

function getAwsCfg(env: any): {
  bucket?: string; region?: string; accessKey?: string; secretKey?: string; errorResponse?: Response;
} {
  const bucket = env.S3_BUCKET;
  const region = env.AWS_REGION;
  const accessKey = env.AWS_ACCESS_KEY_ID;
  const secretKey = env.AWS_SECRET_ACCESS_KEY;

  if (!bucket || !region || !accessKey || !secretKey) {
    return { errorResponse: new Response("Server not configured", { status: 500 }) };
  }
  return { bucket, region, accessKey, secretKey };
}

// ----------------------
// S3 Presign (SigV4) for GET Object
// ----------------------

async function presignS3GetObject(opts: {
  bucket: string;
  region: string;
  key: string;
  accessKey: string;
  secretKey: string;
  expiresSeconds: number;
}) {
  const { bucket, region, key, accessKey, secretKey, expiresSeconds } = opts;

  const service = "s3";
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const now = new Date();

  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  const canonicalUri = "/" + encodeS3Key(key);
  const params: Record<string, string> = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${accessKey}/${credentialScope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSeconds),
    "X-Amz-SignedHeaders": "host"
  };

  const canonicalQueryString = toCanonicalQuery(params);
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = "host";
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest =
    `GET\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const stringToSign =
    `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;

  const signingKey = await getSigningKey(secretKey, dateStamp, region, service);
  const signature = await hmacHex(signingKey, stringToSign);

  const finalQuery = canonicalQueryString + `&X-Amz-Signature=${signature}`;
  return `https://${host}${canonicalUri}?${finalQuery}`;
}

function encodeS3Key(key: string) {
  return key.split("/").map(seg =>
    encodeURIComponent(seg).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
  ).join("/");
}

function toAmzDate(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
}

function toCanonicalQuery(params: Record<string, string>) {
  const keys = Object.keys(params).sort();
  return keys.map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join("&");
}

async function sha256Hex(str: string) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bufToHex(hash);
}

async function hmacHex(keyBytes: Uint8Array, str: string) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(str));
  return bufToHex(sig);
}

async function getSigningKey(secretKey: string, dateStamp: string, regionName: string, serviceName: string) {
  const kDate = await hmacRaw(new TextEncoder().encode("AWS4" + secretKey), dateStamp);
  const kRegion = await hmacRaw(kDate, regionName);
  const kService = await hmacRaw(kRegion, serviceName);
  const kSigning = await hmacRaw(kService, "aws4_request");
  return kSigning;
}

async function hmacRaw(keyBytes: Uint8Array, msg: string) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return new Uint8Array(sig);
}

function bufToHex(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}
