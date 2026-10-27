use super::*;

#[test]
fn pinais_own_repository_is_a_source_url() {
    assert_eq!(
        SourceUrl::parse(PINAI_SOURCE_URL).unwrap().as_str(),
        PINAI_SOURCE_URL
    );
}

#[test]
fn a_source_url_is_an_http_or_https_url_kept_normalised() {
    for (raw, kept) in [
        (
            "https://codeberg.org/aotearoa/pinai",
            "https://codeberg.org/aotearoa/pinai",
        ),
        (
            " http://localhost:3000/pinai ",
            "http://localhost:3000/pinai",
        ),
        ("https://Git.Example.org", "https://git.example.org/"),
        (
            "https://git.example.org/pinai/src/tag/v1.2.0?display=source#readme",
            "https://git.example.org/pinai/src/tag/v1.2.0?display=source#readme",
        ),
    ] {
        assert_eq!(SourceUrl::parse(raw).unwrap().as_str(), kept, "{raw}");
    }
}

#[test]
fn anything_but_an_http_or_https_url_is_refused() {
    for refused in [
        "",
        "github.com/Pina-i/pinai",
        "/source",
        "ftp://git.example.org/pinai",
        "git@github.com:Pina-i/pinai.git",
        "javascript:alert(1)",
        "data:text/html,source",
        "https://someone:secret@git.example.org/pinai",
        "https://someone@git.example.org/pinai",
    ] {
        assert!(SourceUrl::parse(refused).is_err(), "{refused:?}");
    }
}
