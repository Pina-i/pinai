//! The sign-in pages, rendered here with no inline script: the frame every page shares, the
//! request each one carries, their headers, the origin check on their forms, and their assets —
//! see identity-provider/specs/auth.md § 1.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, LazyLock};

use application::auth::ShowSignIn;
use application::identity::{DescribeInstance, InstanceFacts};
use askama::Template;
use axum::extract::{FromRef, FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use domain::auth::{AuthError, AuthorizationRequest, ClientId, CodeChallenge};
use domain::identity::InstanceOrigin;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::ApiError;
use crate::sign_in::{carrying, url_with};

/// What the sign-in pages are built from, and how the session cookie is set.
#[derive(Clone)]
pub struct SignInPages {
    describe: Arc<DescribeInstance>,
    pub(crate) show: Arc<ShowSignIn>,
    origin: InstanceOrigin,
    /// `Secure` cookies: production is served over HTTPS only.
    pub secure_cookies: bool,
}

impl SignInPages {
    pub fn new(
        describe: Arc<DescribeInstance>,
        show: Arc<ShowSignIn>,
        origin: InstanceOrigin,
        secure_cookies: bool,
    ) -> Self {
        Self {
            describe,
            show,
            origin,
            secure_cookies,
        }
    }

    pub(crate) fn host(&self) -> String {
        self.origin.domain().to_string()
    }

    /// The host an address on this instance would have: the domain without its port.
    pub(crate) fn email_host(&self) -> String {
        let host = self.host();
        host.rsplit_once(':')
            .map_or(host.as_str(), |(name, _)| name)
            .to_owned()
    }

    pub(crate) async fn frame(&self, appearance: Appearance) -> Result<Frame, ApiError> {
        let facts = self
            .describe
            .execute(OffsetDateTime::now_utc())
            .await
            .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
        Ok(Frame::new(facts, self.host(), appearance))
    }

    /// A page with no request to carry on: an expired link, a sign-out, an app that can't be
    /// trusted.
    pub(crate) async fn notice(
        &self,
        status: StatusCode,
        notice: Notice,
        appearance: Appearance,
    ) -> Result<Response, ApiError> {
        let page = NoticePage {
            frame: self.frame(appearance).await?,
            title: notice.title,
            text: notice.text,
            back: None,
        };
        Ok(render(status, &page, None))
    }

    /// A request whose client can't be had, or doesn't list its redirect URI: answered here,
    /// since where it says to go can't be trusted.
    pub(crate) async fn misdirected(
        &self,
        error: AuthError,
        appearance: Appearance,
    ) -> Result<Response, ApiError> {
        let status = match error {
            AuthError::UnknownClient => StatusCode::UNAUTHORIZED,
            AuthError::UnregisteredRedirect => StatusCode::BAD_REQUEST,
            other => return Err(ApiError::internal(anyhow::Error::from(other))),
        };
        self.notice(status, UNVERIFIED, appearance).await
    }
}

/// The theme and motif the client last painted, when it said: unknown values are dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Appearance {
    theme: Option<&'static str>,
    motif: Option<&'static str>,
}

const THEMES: [&str; 8] = [
    "pearl-dark",
    "pearl-light",
    "lagoon-dark",
    "lagoon-light",
    "jungle-dark",
    "jungle-light",
    "sand-dark",
    "sand-light",
];
const MOTIFS: [&str; 7] = [
    "kowhaiwhai",
    "raranga",
    "puhoro",
    "tapa1",
    "tapa2",
    "tapa3",
    "tapa4",
];

impl Appearance {
    pub(crate) fn parse(theme: Option<&str>, motif: Option<&str>) -> Self {
        let known = |list: &[&'static str], given: Option<&str>| {
            given.and_then(|given| list.iter().find(|known| **known == given).copied())
        };
        Self {
            theme: known(&THEMES, theme),
            motif: known(&MOTIFS, motif),
        }
    }

    fn theme(&self) -> &'static str {
        self.theme.unwrap_or("pearl-dark")
    }

    fn mode(&self) -> &'static str {
        if self.theme().ends_with("-light") {
            "light"
        } else {
            "dark"
        }
    }

    fn motif(&self) -> &'static str {
        self.motif.unwrap_or("tapa1")
    }

    /// What travels from page to page: only what the client said.
    pub(crate) fn pairs(&self) -> Vec<(&'static str, &'static str)> {
        let mut pairs = Vec::new();
        if let Some(theme) = self.theme {
            pairs.push(("theme", theme));
        }
        if let Some(motif) = self.motif {
            pairs.push(("motif", motif));
        }
        pairs
    }
}

/// The sign-in a page or a form carries along, as it came: checked again wherever it is used.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Carried {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    theme: Option<String>,
    motif: Option<String>,
}

impl Carried {
    /// `None` when a parameter is missing or malformed: a link cut short, or an old one.
    pub(crate) fn request(&self) -> Option<AuthorizationRequest> {
        Some(AuthorizationRequest {
            client: ClientId::parse(self.client_id.as_deref()?).ok()?,
            redirect_uri: self.redirect_uri.clone()?,
            scope: self.scope.clone()?,
            state: self.state.clone()?,
            challenge: CodeChallenge::parse(
                self.code_challenge.as_deref()?,
                self.code_challenge_method.as_deref()?,
            )
            .ok()?,
            nonce: self.nonce.clone(),
        })
    }

    pub(crate) fn appearance(&self) -> Appearance {
        Appearance::parse(self.theme.as_deref(), self.motif.as_deref())
    }
}

/// The request's parameters and the appearance, then `extra`: what a page links and posts on.
pub(crate) fn carried<'a>(
    request: &'a AuthorizationRequest,
    appearance: Appearance,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = carrying(request, &appearance.pairs());
    pairs.extend_from_slice(extra);
    pairs
}

/// One of this instance's pages, with the query given.
pub(crate) fn to(page: &str, pairs: &[(&str, &str)]) -> Response {
    if pairs.is_empty() {
        Redirect::to(page).into_response()
    } else {
        Redirect::to(&url_with(page, pairs)).into_response()
    }
}

/// Back to the client, signed in nowhere — RFC 6749 § 4.1.2.1.
pub(crate) fn cancel(request: &AuthorizationRequest) -> String {
    url_with(
        &request.redirect_uri,
        &[("error", "access_denied"), ("state", &request.state)],
    )
}

/// What every page shows of the instance, and how it is painted.
pub(crate) struct Frame {
    name: String,
    host: String,
    description: String,
    /// The instance said something of itself: `INSTANCE_DESCRIPTION`.
    described: bool,
    people: String,
    open: bool,
    version: &'static str,
    theme: &'static str,
    mode: &'static str,
    motif: &'static str,
    stylesheet: &'static str,
    script: &'static str,
}

impl Frame {
    fn new(facts: InstanceFacts, host: String, appearance: Appearance) -> Self {
        Self {
            name: facts.name,
            host,
            described: facts.description.is_some(),
            description: facts
                .description
                .unwrap_or_else(|| "An identity provider.".to_owned()),
            people: people(facts.people),
            open: facts.open_registrations,
            version: env!("CARGO_PKG_VERSION"),
            theme: appearance.theme(),
            mode: appearance.mode(),
            motif: appearance.motif(),
            stylesheet: STYLESHEET.as_str(),
            script: SCRIPT.as_str(),
        }
    }

    /// The instance's initial, as the invitation's pages set it large.
    pub(crate) fn initial(&self) -> String {
        initial_of(&self.name)
    }
}

/// A name's first letter, upper-cased: what stands for an instance or an account in a badge.
pub(crate) fn initial_of(name: &str) -> String {
    name.chars()
        .next()
        .map(|first| first.to_uppercase().collect())
        .unwrap_or_default()
}

/// How long is left, in days — in hours when under a day: `7 days`, `5 hours`, `1 hour`.
pub(crate) fn time_left(left: time::Duration) -> String {
    let seconds = left.whole_seconds().max(1);
    let hours = (seconds + 3_599) / 3_600;
    let (count, unit) = if hours < 24 {
        (hours, "hour")
    } else {
        ((seconds + 86_399) / 86_400, "day")
    };
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

/// `1 person`, `1,204 people`.
fn people(count: u64) -> String {
    let digits = count.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if count == 1 {
        format!("{grouped} person")
    } else {
        format!("{grouped} people")
    }
}

#[derive(Template)]
#[template(path = "sign-in/login.html")]
pub(crate) struct LoginPage<'a> {
    pub frame: Frame,
    pub back: String,
    /// The app asking, by the name its document gives…
    pub app_name: String,
    /// …and where it lives, unless that is this instance (the desktop app's document).
    pub app_host: Option<String>,
    pub register: bool,
    pub sign_in_href: String,
    pub register_href: String,
    pub alert: Option<&'static str>,
    pub note: Option<&'static str>,
    /// The field the alert is about, or "".
    pub bad: &'static str,
    pub email_host: String,
    pub carried: Vec<(&'a str, &'a str)>,
}

#[derive(Template)]
#[template(path = "sign-in/verify-email.html")]
pub(crate) struct VerifyEmailPage<'a> {
    pub frame: Frame,
    pub back: String,
    pub email: Option<String>,
    pub status: String,
    pub failed: bool,
    pub resent: bool,
    pub carried: Vec<(&'a str, &'a str)>,
}

#[derive(Template)]
#[template(path = "sign-in/second-factor.html")]
pub(crate) struct SecondFactorPage<'a> {
    pub frame: Frame,
    pub back: String,
    pub recovery: bool,
    pub switch_href: String,
    pub alert: Option<&'static str>,
    pub carried: Vec<(&'a str, &'a str)>,
}

#[derive(Template)]
#[template(path = "sign-in/invitation.html")]
pub(crate) struct InvitationPage {
    pub frame: Frame,
    /// Its creator's display name — never a handle or an address.
    pub inviter: Option<String>,
    pub expires_in: String,
    pub sign_up_href: String,
}

#[derive(Template)]
#[template(path = "sign-in/invited-sign-up.html")]
pub(crate) struct InvitedSignUpPage {
    pub frame: Frame,
    pub inviter: Option<String>,
    pub inviter_initial: String,
    /// The invitation's own page.
    pub back_href: String,
    pub action: String,
    /// Where the web app opens on this instance, when one is known: the button says the person
    /// goes on there, and someone with an account already signs in there instead.
    pub web_app: Option<String>,
    pub alert: Option<&'static str>,
    /// The field the alert is about, or "".
    pub bad: &'static str,
    /// What was typed, kept but the password.
    pub display_name: String,
    pub email: String,
    pub email_host: String,
}

#[derive(Template)]
#[template(path = "sign-in/account-ready.html")]
pub(crate) struct AccountReadyPage {
    pub frame: Frame,
    pub email: String,
}

#[derive(Template)]
#[template(path = "sign-in/notice.html")]
pub(crate) struct NoticePage {
    pub frame: Frame,
    pub title: &'static str,
    pub text: &'static str,
    pub back: Option<String>,
}

/// A notice's fixed words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Notice {
    pub title: &'static str,
    pub text: &'static str,
}

pub(crate) const UNVERIFIED: Notice = Notice {
    title: "This app couldn't be verified",
    text: "Its description couldn't be read, or doesn't list where it asked to go back to. \
           Go back to the app and try again.",
};

/// The one answer for an invitation that is unknown, used, revoked or expired: which, the link
/// never tells.
pub(crate) const INVITATION_UNUSABLE: Notice = Notice {
    title: "This invitation can no longer be used",
    text: "Ask the person who sent it for a new one.",
};

pub(crate) const SIGNED_OUT: Notice = Notice {
    title: "You're signed out",
    text: "You can close this page.",
};

/// The page a sign-in link with no request left lands on, by what ended it.
pub(crate) fn expired(code: Option<&str>) -> Notice {
    match code {
        Some("ticket_expired") => Notice {
            title: "This sign-in has expired",
            text: "Go back to the app and sign in again.",
        },
        Some("ticket_exhausted") => Notice {
            title: "Too many attempts",
            text: "Go back to the app and sign in again.",
        },
        _ => Notice {
            title: "This sign-in link has expired",
            text: "Go back to the app and try again.",
        },
    }
}

/// The login page's error codes: the sentence, and the field it is about.
pub(crate) fn login_alert(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "invalid_credentials" => ("Invalid email or password", ""),
        "rate_limited" => ("Too many attempts — try again in a minute", ""),
        "missing_field" => ("Fill in every field", ""),
        "invalid_display_name" => ("Display name: 1–50 characters", "display_name"),
        "invalid_email" => ("Enter a valid email address", "email"),
        "weak_password" => ("Password must be at least 8 characters", "password"),
        "email_taken" => ("Email already registered", "email"),
        "signup_expired" => ("This sign-up has expired — register again", ""),
        _ => return None,
    })
}

pub(crate) fn login_note(code: &str) -> Option<&'static str> {
    match code {
        "already_verified" => Some("This address is confirmed already — sign in to continue"),
        "no_code_needed" => Some("This account signs in with its password — sign in to continue"),
        _ => None,
    }
}

/// The code page's status line, and whether it reports a failure.
pub(crate) fn verify_status(
    error: Option<&str>,
    notice: Option<&str>,
    left: Option<&str>,
) -> (String, bool) {
    let failure = match error {
        Some("code_format") => Some("Enter the 6-digit code".to_owned()),
        Some("code_expired") => Some("Code expired — request a new one".to_owned()),
        Some("code_exhausted") => Some("Too many attempts — request a new code".to_owned()),
        Some("code_incorrect") => Some(match left.and_then(|left| left.parse::<u32>().ok()) {
            Some(1) => "Incorrect code — 1 attempt left".to_owned(),
            Some(left) => format!("Incorrect code — {left} attempts left"),
            None => "Incorrect code".to_owned(),
        }),
        Some("code_used") => Some("Code already used — try signing in".to_owned()),
        Some("too_many_codes") => Some("Too many codes sent — wait a few minutes".to_owned()),
        _ => None,
    };
    if let Some(failure) = failure {
        return (failure, true);
    }
    let status = match notice {
        Some("code_resent") => "New code sent. The previous one no longer works.",
        Some("confirm_email") => "Confirm your email to finish signing in.",
        _ => "Codes expire in 10 minutes.",
    };
    (status.to_owned(), false)
}

pub(crate) fn totp_alert(code: &str) -> Option<&'static str> {
    match code {
        "totp_incorrect" => Some("Incorrect code"),
        "recovery_unknown" => Some("Recovery code not recognised"),
        "totp_missing" => Some("Enter a code or a recovery code"),
        _ => None,
    }
}

/// A page with the headers every sign-in page carries. `returns_to` is the client's redirect URI
/// when a form on the page ends there: Chrome holds the redirect after a POST to `form-action`.
pub(crate) fn render(
    status: StatusCode,
    page: &impl Template,
    returns_to: Option<&str>,
) -> Response {
    let html = match page.render() {
        Ok(html) => html,
        Err(error) => return ApiError::internal(anyhow::Error::from(error)).into_response(),
    };
    let form_action = match returns_to.and_then(|uri| url::Url::parse(uri).ok()) {
        Some(uri) if uri.origin().is_tuple() => {
            format!("'self' {}", uri.origin().ascii_serialization())
        }
        Some(uri) => format!("'self' {}:", uri.scheme()),
        None => "'self'".to_owned(),
    };
    let policy = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; \
         form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
    );
    let mut response = (status, html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // Not `no-referrer`: a browser then posts the page's forms as `Origin: null`.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A page whose URL carries an invitation's token and that holds no form: no `Referer` takes the
/// token anywhere.
pub(crate) fn unreferred(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// A form posted from one of this instance's own pages. Refused when the browser says it came
/// from elsewhere; a request saying neither — a test, a script — is let through, since a browser
/// always says. `Origin: null` says nothing either way (a sandboxed frame sends it, and a
/// page under `no-referrer` would too): `Sec-Fetch-Site` decides, and without it, it is refused.
pub(crate) struct SameOrigin;

impl<S> FromRequestParts<S> for SameOrigin
where
    InstanceOrigin: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ours = InstanceOrigin::from_ref(state).base_url();
        let origin = parts.headers.get(header::ORIGIN);
        let site = parts.headers.get("sec-fetch-site");
        let elsewhere = match (origin, site) {
            (Some(origin), _) if origin != "null" => origin != ours.as_str(),
            (_, Some(site)) => site != "same-origin",
            (Some(_), None) => true,
            (None, None) => false,
        };
        if elsewhere {
            Err((
                StatusCode::FORBIDDEN,
                "This form was sent from another site",
            )
                .into_response())
        } else {
            Ok(Self)
        }
    }
}

macro_rules! asset {
    ($path:literal, $kind:literal) => {
        (
            $path,
            $kind,
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/", $path)).as_slice(),
        )
    };
}

/// Embedded in the binary: an instance serves its pages whatever its working directory.
const ASSETS: [(&str, &str, &[u8]); 23] = [
    asset!("sign-in.css", "text/css; charset=utf-8"),
    asset!("sign-in.js", "text/javascript; charset=utf-8"),
    asset!("favicon.svg", "image/svg+xml"),
    asset!("grain.gif", "image/gif"),
    asset!("fonts/dm-sans.woff2", "font/woff2"),
    asset!("fonts/dm-sans-ext.woff2", "font/woff2"),
    asset!("fonts/instrument-serif.woff2", "font/woff2"),
    asset!("fonts/instrument-serif-ext.woff2", "font/woff2"),
    asset!("fonts/instrument-serif-italic.woff2", "font/woff2"),
    asset!("fonts/instrument-serif-italic-ext.woff2", "font/woff2"),
    asset!("fonts/azeret-mono.woff2", "font/woff2"),
    asset!("fonts/azeret-mono-ext.woff2", "font/woff2"),
    asset!("motifs/kowhaiwhai.svg", "image/svg+xml"),
    asset!("motifs/raranga.svg", "image/svg+xml"),
    asset!("motifs/puhoro.svg", "image/svg+xml"),
    asset!("motifs/puhoro-band.svg", "image/svg+xml"),
    asset!("motifs/tapa1.svg", "image/svg+xml"),
    asset!("motifs/tapa2.svg", "image/svg+xml"),
    asset!("motifs/tapa3.svg", "image/svg+xml"),
    asset!("motifs/tapa4.svg", "image/svg+xml"),
    asset!("fonts/OFL-dmsans.txt", "text/plain; charset=utf-8"),
    asset!("fonts/OFL-instrumentserif.txt", "text/plain; charset=utf-8"),
    asset!("fonts/OFL-azeretmono.txt", "text/plain; charset=utf-8"),
];

/// The stylesheet's and the script's URLs, named by their content: a release that changes one
/// has it fetched anew.
static STYLESHEET: LazyLock<String> = LazyLock::new(|| versioned(0));
static SCRIPT: LazyLock<String> = LazyLock::new(|| versioned(1));

fn versioned(asset: usize) -> String {
    let (path, _, bytes) = ASSETS[asset];
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("/assets/{path}?v={:016x}", hasher.finish())
}

/// `GET /assets/{*path}` — the pages' stylesheet, fonts, motifs and grain.
pub async fn asset(Path(path): Path<String>) -> Response {
    let Some((_, kind, bytes)) = ASSETS.iter().find(|(name, _, _)| *name == path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, *kind),
            (header::CACHE_CONTROL, "public, max-age=86400"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        *bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests;
