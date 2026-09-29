use super::*;

#[test]
fn a_validation_error_names_the_field_and_the_reason() {
    let error = ValidationError::new("handle", "3–32 characters");

    assert_eq!(error.to_string(), "handle: 3–32 characters");
}
