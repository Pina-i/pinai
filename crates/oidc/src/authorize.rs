use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use idp_db::repos::{auth_codes, clients, users};

use crate::{
    cookies::{urlencoded, SESSION_COOKIE_NAME},
    AppState, OidcError,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// GET /authorize
///
/// Validates the authorization request. If the user already has a valid session
/// cookie, issues an auth code immediately (SSO). Otherwise serves the login form.
#[tracing::instrument(skip_all, fields(
    client_id = %params.client_id,
    redirect_uri = %params.redirect_uri,
    response_type = %params.response_type,
))]
pub async fn get_authorize(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, OidcError> {
    // 1. Validate response_type
    if params.response_type != "code" {
        return Err(OidcError::invalid_request("response_type must be 'code'"));
    }

    // 2. Validate code_challenge_method (S256 only — plain is rejected)
    if params.code_challenge_method != "S256" {
        return Err(OidcError::invalid_request(
            "code_challenge_method must be 'S256'",
        ));
    }

    // 3. Validate client exists
    let client = clients::find_client_by_id(&state.pool, &params.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;

    tracing::debug!("client validated");

    // 4. Validate redirect_uri (case-sensitive exact match — RFC 6749 §3.1.2)
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err(OidcError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }

    // 5. Check for an existing session cookie (SSO — skip login form)
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Ok(user_id) = Uuid::parse_str(cookie.value()) {
            if users::find_by_id(&state.pool, user_id)
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?
                .is_some()
            {
                tracing::debug!(user_id = %user_id, "valid session cookie, issuing code via SSO");

                let code = generate_and_store_code(
                    &state.pool,
                    user_id,
                    &params.client_id,
                    &params.redirect_uri,
                    &params.code_challenge,
                    &params.code_challenge_method,
                    &params.scope,
                    params.nonce.as_deref(),
                )
                .await?;

                tracing::info!(user_id = %user_id, "SSO: auth code issued, redirecting");

                let redirect_url = format!(
                    "{}?code={}&state={}",
                    params.redirect_uri,
                    urlencoded(&code),
                    urlencoded(&params.state),
                );
                return Ok(Redirect::to(&redirect_url).into_response());
            }
        }
    }

    tracing::debug!("no session cookie, serving login form");

    // 6. Serve the login form with all OIDC params as hidden fields
    let nonce_field = params
        .nonce
        .as_deref()
        .map(|n| format!(r#"<input type="hidden" name="nonce" value="{}">"#, html_escape(n)))
        .unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in — Pīna'i</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0a0a0f;
      font-family: system-ui, -apple-system, sans-serif;
      color: #e8e8f0;
    }}
    .card {{
      background: #111118;
      border: 1px solid #1e1e2e;
      padding: 40px;
      width: 100%;
      max-width: 400px;
    }}
    h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 8px; }}
    .subtitle {{ color: #6b6b8a; font-size: 0.88rem; margin-bottom: 32px; }}
    .tabs {{
      display: flex;
      gap: 0;
      margin-bottom: 28px;
      border-bottom: 1px solid #1e1e2e;
    }}
    .tab {{
      flex: 1;
      padding: 10px;
      text-align: center;
      cursor: pointer;
      font-size: 0.85rem;
      color: #6b6b8a;
      border-bottom: 2px solid transparent;
      margin-bottom: -1px;
      background: none;
      border-top: none;
      border-left: none;
      border-right: none;
      color: inherit;
    }}
    .tab.active {{ color: #5865f2; border-bottom-color: #5865f2; }}
    label {{ display: block; font-size: 0.78rem; color: #6b6b8a; margin-bottom: 6px; }}
    input[type=text], input[type=email], input[type=password] {{
      width: 100%;
      padding: 10px 14px;
      background: #0a0a0f;
      border: 1px solid #1e1e2e;
      color: #e8e8f0;
      font-size: 0.9rem;
      margin-bottom: 16px;
      outline: none;
    }}
    input:focus {{ border-color: #5865f2; }}
    button[type=submit] {{
      width: 100%;
      padding: 12px;
      background: #5865f2;
      color: #fff;
      border: none;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
    }}
    button[type=submit]:hover {{ background: #4752c4; }}
    .error {{ color: #ed4245; font-size: 0.82rem; margin-bottom: 16px; }}
  </style>
</head>
<body>
<div class="card">
  <h1>Pīna'i</h1>
  <p class="subtitle">Sign in to continue</p>

  <div class="tabs">
    <button type="button" class="tab active" onclick="showTab('login')">Sign in</button>
    <button type="button" class="tab" onclick="showTab('register')">Register</button>
  </div>

  <!-- LOGIN FORM -->
  <form id="login-form" action="/login" method="POST">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    {nonce_field}

    <label for="login-username">Username</label>
    <input type="text" id="login-username" name="username" required autocomplete="username">

    <label for="login-password">Password</label>
    <input type="password" id="login-password" name="password" required autocomplete="current-password">

    <button type="submit">Sign in</button>
  </form>

  <!-- REGISTER FORM -->
  <form id="register-form" action="/register-and-login" method="POST" style="display:none">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    {nonce_field}

    <label for="reg-username">Username</label>
    <input type="text" id="reg-username" name="username" required autocomplete="username">

    <label for="reg-email">Email</label>
    <input type="email" id="reg-email" name="email" required autocomplete="email">

    <label for="reg-password">Password</label>
    <input type="password" id="reg-password" name="password" required autocomplete="new-password">

    <button type="submit">Create account</button>
  </form>
</div>

<script>
  function showTab(tab) {{
    document.getElementById('login-form').style.display = tab === 'login' ? '' : 'none';
    document.getElementById('register-form').style.display = tab === 'register' ? '' : 'none';
    document.querySelectorAll('.tab').forEach((el, i) => {{
      el.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'register' && i === 1));
    }});
  }}
</script>
</body>
</html>"#,
        client_id = html_escape(&params.client_id),
        redirect_uri = html_escape(&params.redirect_uri),
        scope = html_escape(&params.scope),
        state = html_escape(&params.state),
        code_challenge = html_escape(&params.code_challenge),
        code_challenge_method = html_escape(&params.code_challenge_method),
        nonce_field = nonce_field,
    );

    Ok(Html(html).into_response())
}

/// Generate a random auth code and persist it in the database.
async fn generate_and_store_code(
    pool: &idp_db::PgPool,
    user_id: Uuid,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    scope: &str,
    nonce: Option<&str>,
) -> Result<String, OidcError> {
    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let code = Base64UrlUnpadded::encode_string(&code_bytes);

    auth_codes::create_code(
        pool,
        &code,
        client_id,
        user_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        scope,
        nonce,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(code)
}

/// Minimal HTML escaping to prevent XSS when embedding values in HTML attributes.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
