use serde_json::Value;

use crate::ValidationError;

/// A change to the settings: the sections it names each replace the stored one whole.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingsPatch(Value);

impl SettingsPatch {
    /// A non-empty object whose every value is itself an object: a section is replaced whole,
    /// so a scalar there would erase a section's shape.
    pub fn parse(change: Value) -> Result<Self, ValidationError> {
        let sections = change
            .as_object()
            .ok_or_else(|| refusal("settings must be a JSON object"))?;
        if sections.is_empty() {
            return Err(refusal("settings change is empty"));
        }
        if let Some((name, _)) = sections.iter().find(|(_, section)| !section.is_object()) {
            return Err(refusal(format!(
                "settings section `{name}` must be an object"
            )));
        }
        Ok(Self(change))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

fn refusal(reason: impl Into<String>) -> ValidationError {
    ValidationError::new("settings", reason)
}

#[cfg(test)]
mod tests;
