use super::*;

#[test]
fn a_name_is_trimmed_and_counted_in_characters() {
    assert_eq!(readable_name("  alice \n", 50), Ok("alice"));
    assert_eq!(readable_name(&"é".repeat(5), 5), Ok("ééééé"));
    assert_eq!(
        readable_name(&"é".repeat(6), 5),
        Err(UnreadableName::TooLong)
    );
}

#[test]
fn a_name_of_nothing_but_whitespace_or_joiners_is_blank() {
    for blank in ["", "   ", "\t\n", "\u{200D}", " \u{200C}\u{200D} "] {
        assert_eq!(
            readable_name(blank, 50),
            Err(UnreadableName::Blank),
            "{blank:?}"
        );
    }
}

#[test]
fn a_control_character_is_refused() {
    for name in ["bob\u{0}", "bob\nalice", "bob\u{7F}", "bo\u{85}b"] {
        assert_eq!(
            readable_name(name, 50),
            Err(UnreadableName::ControlCharacter),
            "{name:?}"
        );
    }
}

#[test]
fn every_character_that_shows_nothing_or_turns_the_text_is_refused() {
    let invisible = [
        '\u{200B}', '\u{061C}', '\u{2060}', '\u{FEFF}', '\u{00AD}', '\u{180E}',
    ]
    .into_iter()
    .chain('\u{200E}'..='\u{200F}')
    .chain('\u{202A}'..='\u{202E}')
    .chain('\u{2061}'..='\u{2064}')
    .chain('\u{2066}'..='\u{2069}')
    .chain('\u{2028}'..='\u{2029}')
    .chain(['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}', '\u{2800}']);

    for c in invisible {
        assert_eq!(
            readable_name(&format!("bo{c}b"), 50),
            Err(UnreadableName::InvisibleCharacter),
            "{c:?}"
        );
        // The line and paragraph separators are whitespace too: alone, they are trimmed away.
        let alone = match c.is_whitespace() {
            true => UnreadableName::Blank,
            false => UnreadableName::InvisibleCharacter,
        };
        assert_eq!(readable_name(&c.to_string(), 50), Err(alone), "{c:?} alone");
    }
}

#[test]
fn the_zero_width_joiners_stay_within_a_name() {
    let coder = "\u{1F469}\u{200D}\u{1F4BB} alice";

    assert_eq!(readable_name(coder, 50), Ok(coder));
    assert_eq!(readable_name("ab\u{200C}cd", 50), Ok("ab\u{200C}cd"));
}
