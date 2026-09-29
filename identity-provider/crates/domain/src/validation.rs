/// Why a raw value could not become a domain type.
#[derive(Debug, thiserror::Error)]
#[error("{field}: {reason}")]
pub struct ValidationError {
    pub field: &'static str,
    pub reason: String,
}

impl ValidationError {
    pub fn new(field: &'static str, reason: impl Into<String>) -> Self {
        Self {
            field,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests;
