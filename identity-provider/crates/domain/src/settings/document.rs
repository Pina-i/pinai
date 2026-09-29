use serde_json::Value;

/// The whole settings document of an account, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingsDocument(Value);

impl SettingsDocument {
    /// The largest document an account may keep, in bytes of JSON.
    pub const MAX_BYTES: usize = 16 * 1024;

    /// The document of an account that never saved any settings.
    pub fn empty() -> Self {
        Self(Value::Object(Default::default()))
    }

    pub fn from_value(document: Value) -> Self {
        Self(document)
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }
}
