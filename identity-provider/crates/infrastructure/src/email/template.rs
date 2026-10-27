//! Hand-rolled email templates. No Handlebars / Tera — at this scale the
//! string-substitution overhead isn't worth a dependency.

pub struct SignupOtpView<'a> {
    pub display_name: &'a str,
    pub code: &'a str,
    pub issuer_host: &'a str,
}

pub fn signup_otp_subject(view: &SignupOtpView<'_>) -> String {
    format!("Confirm your Pīna'i account · {}", view.code)
}

pub fn signup_otp_plaintext(view: &SignupOtpView<'_>) -> String {
    format!(
        "Hi {name},\n\n\
         Your Pīna'i confirmation code is: {code}\n\n\
         Enter it on the sign-up page within 10 minutes to finish creating your\n\
         account. If you didn't start a sign-up at {host}, you can ignore this\n\
         message.\n\n\
         — Pīna'i",
        name = view.display_name,
        code = view.code,
        host = view.issuer_host,
    )
}

pub fn signup_otp_html(view: &SignupOtpView<'_>) -> String {
    format!(
        "<!doctype html>\n<html><body style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.55; color: #222; padding: 32px;\">\
         <p>Hi {name},</p>\
         <p>Your Pīna'i confirmation code is:</p>\
         <p style=\"font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 28px; letter-spacing: 0.16em; padding: 12px 18px; background: #f4f4f4; border-radius: 6px; display: inline-block;\">{code}</p>\
         <p>Enter it on the sign-up page within 10 minutes to finish creating your account.</p>\
         <p style=\"color: #888; font-size: 13px;\">If you didn't start a sign-up at {host}, you can ignore this message.</p>\
         <p style=\"color: #888; font-size: 13px;\">— Pīna'i</p>\
         </body></html>",
        name = html_escape(view.display_name),
        code = view.code,
        host = html_escape(view.issuer_host),
    )
}

pub struct ResetLinkView<'a> {
    pub display_name: &'a str,
    /// The instance's name.
    pub instance: &'a str,
    pub link: &'a str,
    /// How long the link works.
    pub minutes: i64,
    pub issuer_host: &'a str,
}

pub fn reset_link_subject(view: &ResetLinkView<'_>) -> String {
    format!("Reset your password on {}", view.instance)
}

pub fn reset_link_plaintext(view: &ResetLinkView<'_>) -> String {
    format!(
        "Hi {name},\n\n\
         To choose a new password for your account on {instance}, open this link:\n\n\
         {link}\n\n\
         It works once, for {minutes} minutes.\n\n\
         If you didn't ask for it, ignore this email: your password stays as it is.\n\n\
         — {host}",
        name = view.display_name,
        instance = view.instance,
        link = view.link,
        minutes = view.minutes,
        host = view.issuer_host,
    )
}

pub fn reset_link_html(view: &ResetLinkView<'_>) -> String {
    format!(
        "<!doctype html>\n<html><body style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.55; color: #222; padding: 32px;\">\
         <p>Hi {name},</p>\
         <p>To choose a new password for your account on {instance}, open this link:</p>\
         <p><a href=\"{link}\" style=\"display: inline-block; padding: 12px 20px; background: #8e3b5f; color: #fff; border-radius: 999px; text-decoration: none; font-weight: 600;\">Choose a new password</a></p>\
         <p style=\"font-size: 13px; word-break: break-all;\"><a href=\"{link}\" style=\"color: #555;\">{link}</a></p>\
         <p>It works once, for {minutes} minutes.</p>\
         <p style=\"color: #888; font-size: 13px;\">If you didn't ask for it, ignore this email: your password stays as it is.</p>\
         <p style=\"color: #888; font-size: 13px;\">— {host}</p>\
         </body></html>",
        name = html_escape(view.display_name),
        instance = html_escape(view.instance),
        link = html_escape(view.link),
        minutes = view.minutes,
        host = html_escape(view.issuer_host),
    )
}

/// Minimal HTML escape — just the four characters that can break out of text
/// nodes. Codes are numeric so they need no escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
