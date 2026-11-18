//! The local accounts' errors at the HTTP edge.

use domain::identity::AccountsError;

use crate::ApiError;

impl From<AccountsError> for ApiError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => ApiError::internal(e),
        }
    }
}
