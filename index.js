import express from "express";
import { URLSearchParams } from "url";
import crypto from "node:crypto";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());

const supportedProviders = ["github"];

const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
};

const logError = (message, error) => {
  console.error(message, error);
};

const generateCSRFToken = () => {
  return crypto.randomUUID().replaceAll("-", "");
};

const outputHTML = ({ provider = "unknown", token, error, errorCode }) => {
  const state = error ? "error" : "success";
  const content = error ? { provider, error, errorCode } : { provider, token };

  return `
    <!doctype html><html><head><meta charset="utf-8"><title>OAuth Response</title></head><body><script>
      (() => {
        window.addEventListener('message', ({ data, origin }) => {
          if (data === 'authorizing:${provider}') {
            window.opener?.postMessage(
              'authorization:${provider}:${state}:${JSON.stringify(content)}',
              origin
            );
          }
        });
        window.opener?.postMessage('authorizing:${provider}', '*');
      })();
    </script></body></html>
  `;
};

const outputHTMLError = ({ provider, error, errorCode }) => {
  logError(`Error for provider ${provider}:`, { error, errorCode });
  return outputHTML({ provider, error, errorCode });
};

app.get(["/auth"], (req, res) => {
  const { provider, site_id: domain } = req.query;

  if (!provider || !supportedProviders.includes(provider)) {
    const html = outputHTMLError({
      error: "Your Git backend is not supported by the authenticator.",
      errorCode: "UNSUPPORTED_BACKEND",
    });
    res.status(400).send(html);
    return;
  }

  const {
    ALLOWED_DOMAINS,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = "github.com",
  } = process.env;

  if (
    ALLOWED_DOMAINS &&
    !ALLOWED_DOMAINS.split(/,/).some((str) =>
      (domain ?? "").match(
        new RegExp(`^${escapeRegExp(str.trim()).replace("\\*", ".+")}$`)
      )
    )
  ) {
    const html = outputHTMLError({
      provider,
      error: "Your domain is not allowed to use the authenticator.",
      errorCode: "UNSUPPORTED_DOMAIN",
    });
    res.status(400).send(html);
    return;
  }

  const csrfToken = generateCSRFToken();
  let authURL = "";

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    const html = outputHTMLError({
      provider,
      error: "OAuth app client ID or secret is not configured.",
      errorCode: "MISCONFIGURED_CLIENT",
    });
    res.status(500).send(html);
    return;
  }

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope: "repo,user",
    state: csrfToken,
  });

  authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;

  res.cookie("csrf-token", `${provider}_${csrfToken}`, {
    httpOnly: true,
    maxAge: 600000, // 10 minutes
    sameSite: "Lax",
    secure: true,
  });

  res.set(securityHeaders).redirect(authURL);
});

app.get(["/callback"], async (req, res) => {
  const { code, state } = req.query;
  const csrfTokenCookie = req.cookies["csrf-token"];
  console.log(csrfTokenCookie);
  const [provider, csrfToken] =
    csrfTokenCookie?.match(/([a-z-]+?)_([0-9a-f]{32})/) ?? [];

  if (!provider || !supportedProviders.includes(provider)) {
    const html = outputHTMLError({
      error: "Your Git backend is not supported by the authenticator.",
      errorCode: "UNSUPPORTED_BACKEND",
    });
    res.status(400).send(html);
    return;
  }

  if (!code || !state) {
    const html = outputHTMLError({
      provider,
      error: "Failed to receive an authorization code. Please try again later.",
      errorCode: "AUTH_CODE_REQUEST_FAILED",
    });
    res.status(400).send(html);
    return;
  }

  if (!csrfToken || state !== csrfToken) {
    const html = outputHTMLError({
      provider,
      error: "Potential CSRF attack detected. Authentication flow aborted.",
      errorCode: "CSRF_DETECTED",
    });
    res.status(400).send(html);
    return;
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = "github.com",
  } = process.env;

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    const html = outputHTMLError({
      provider,
      error: "OAuth app client ID or secret is not configured.",
      errorCode: "MISCONFIGURED_CLIENT",
    });
    res.status(500).send(html);
    return;
  }

  const tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
  const requestBody = {
    code,
    client_id: GITHUB_CLIENT_ID,
    client_secret: GITHUB_CLIENT_SECRET,
  };

  let response;
  let token = "";
  let error = "";

  try {
    response = await fetch(tokenURL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });
  } catch (err) {
    logError("Token request failed:", err);
    const html = outputHTMLError({
      provider,
      error: "Failed to request an access token. Please try again later.",
      errorCode: "TOKEN_REQUEST_FAILED",
    });
    res.status(500).send(html);
    return;
  }

  if (!response) {
    const html = outputHTMLError({
      provider,
      error: "Failed to request an access token. Please try again later.",
      errorCode: "TOKEN_REQUEST_FAILED",
    });
    res.status(500).send(html);
    return;
  }

  try {
    ({ access_token: token, error } = await response.json());
  } catch (err) {
    logError("Malformed response:", err);
    const html = outputHTMLError({
      provider,
      error: "Server responded with malformed data. Please try again later.",
      errorCode: "MALFORMED_RESPONSE",
    });
    res.status(500).send(html);
    return;
  }

  const html = outputHTML({ provider, token, error });
  res.set(securityHeaders).send(html);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
