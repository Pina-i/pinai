use std::sync::Arc;

use domain::auth::{AuthError, OtpCode, SignupMailer};

/// `POST /dev/send-test-email`, on a development instance only: a signup mail with a fixed code,
/// to check the SMTP path.
pub struct SendTestMail {
    mailer: Arc<dyn SignupMailer>,
}

impl SendTestMail {
    pub fn new(mailer: Arc<dyn SignupMailer>) -> Self {
        Self { mailer }
    }

    pub async fn execute(&self, to: &str, name: &str) -> Result<(), AuthError> {
        let code = OtpCode::parse("123456").expect("six digits");
        self.mailer.send_code(to, name, &code).await
    }
}
