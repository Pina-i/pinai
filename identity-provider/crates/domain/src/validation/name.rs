/// Why a name can't be read as what it is. Each kind of name words it its own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableName {
    Blank,
    ControlCharacter,
    InvisibleCharacter,
    TooLong,
}

/// identity-provider/specs/identity.md § 5, "Names people read".
pub fn readable_name(raw: &str, max: usize) -> Result<&str, UnreadableName> {
    let name = raw.trim();
    if name.chars().all(|c| c.is_whitespace() || is_joiner(c)) {
        return Err(UnreadableName::Blank);
    }
    if name.chars().any(char::is_control) {
        return Err(UnreadableName::ControlCharacter);
    }
    if name.chars().any(is_invisible) {
        return Err(UnreadableName::InvisibleCharacter);
    }
    if name.chars().count() > max {
        return Err(UnreadableName::TooLong);
    }
    Ok(name)
}

/// Emoji sequences and some scripts need them, so they stay — but they name nothing alone.
fn is_joiner(c: char) -> bool {
    matches!(c, '\u{200C}' | '\u{200D}')
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200E}'..='\u{200F}'
            | '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{2028}'..='\u{2029}'
            | '\u{00AD}'
            | '\u{180E}'
            | '\u{2061}'..='\u{2064}'
            // Hangul fillers and the blank braille pattern: letters that draw nothing.
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{2800}'
    )
}

#[cfg(test)]
mod tests;
